package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	terminal "golang.org/x/term"

	"github.com/jonhadfield/azwaf/session"
)

const (
	blockBlobUploadBlockSize = 4 * 1024 * 1024
	blockBlobParallelism     = 16
	defaultTerminalWidth     = 80
)

// BackupPoliciesInput are the arguments provided to the BackupPolicies function.
type BackupPoliciesInput struct {
	BaseCLIInput
	// Session optionally provides a pre-configured session; when nil a new
	// one is created. Tests inject a fake-backed session here.
	Session                  *session.Session
	Path                     string
	RIDs                     []string
	StorageAccountResourceID string
	ContainerURL             string
	FailFast                 bool
}

func (in *BackupPoliciesInput) Validate() error {
	if in.SubscriptionID == "" && len(in.RIDs) == 0 {
		return fmt.Errorf("%s - subscription-id required if resource ids not specified",
			helpers.GetFunctionName())
	}

	// a subscription id is optional when resource ids are supplied (each id
	// carries its own), but when provided it must be well-formed
	if in.SubscriptionID != "" {
		if err := validateSubscriptionID(in.SubscriptionID); err != nil {
			return err
		}
	}

	return nil
}

// BackupPolicies retrieves policies within a subscription and writes them, with meta-data, to individual json files.
// Both Azure Front Door and Azure Application Gateway WAF policies are
// supported; the resource type embedded in each resource id determines which
// API the policy is fetched from. When no resource ids are supplied, every WAF
// policy of either type within the subscription is backed up.
// destination pairs the storage client with the three settings
// BackupPoliciesInput already carried, so the five travel together from here
// down rather than as positional arguments.
func (in *BackupPoliciesInput) destination(blobClient *azblob.Client, containerName string) BackupDestination {
	return BackupDestination{
		BlobClient:    blobClient,
		ContainerName: containerName,
		Path:          in.Path,
		FailFast:      in.FailFast,
		Quiet:         in.Quiet,
	}
}

func BackupPolicies(in *BackupPoliciesInput) error {
	funcName := helpers.GetFunctionName()

	if err := in.Validate(); err != nil {
		return err
	}

	s := in.Session
	if s == nil {
		var serr error

		s, serr = session.New()
		if serr != nil {
			return serr
		}
	}

	// fail if no destination at all was provided
	if in.Path == "" && in.ContainerURL == "" {
		return fmt.Errorf(
			"%s - either path or storage account details are required",
			funcName)
	}

	if len(in.RIDs) == 0 && in.SubscriptionID == "" {
		return fmt.Errorf(
			"%s - either subscription id or resource ids are required",
			funcName)
	}

	fdRIDs, appgwRIDs := partitionRIDsByWAFType(in.RIDs)

	var (
		fdPolicies    []WrappedPolicy
		appgwPolicies []WrappedAppGWPolicy
		err           error
	)

	switch {
	case len(in.RIDs) == 0:
		// no filter: fetch every FD and every AppGW WAF policy in the subscription
		var fd GetWrappedPoliciesOutput
		fd, err = GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
			SubscriptionID: in.SubscriptionID,
			AppVersion:     in.AppVersion,
			Config:         in.ConfigPath,
		})
		if err != nil {
			return err
		}
		fdPolicies = fd.Policies

		appgwPolicies, err = GetWrappedAppGWPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
			SubscriptionID: in.SubscriptionID,
			AppVersion:     in.AppVersion,
		})
		if err != nil {
			return err
		}
	default:
		if len(fdRIDs) > 0 {
			var fd GetWrappedPoliciesOutput
			fd, err = GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
				SubscriptionID:    in.SubscriptionID,
				AppVersion:        in.AppVersion,
				FilterResourceIDs: fdRIDs,
				Config:            in.ConfigPath,
			})
			if err != nil {
				return err
			}
			fdPolicies = fd.Policies
		}

		if len(appgwRIDs) > 0 {
			appgwPolicies, err = GetWrappedAppGWPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
				SubscriptionID:    in.SubscriptionID,
				AppVersion:        in.AppVersion,
				FilterResourceIDs: appgwRIDs,
			})
			if err != nil {
				return err
			}
		}
	}

	logging.Debugf("%s | retrieved %d FrontDoor and %d AppGW policies", funcName, len(fdPolicies), len(appgwPolicies))

	blobClient, containerName, err := newBackupBlobClient(s, in.StorageAccountResourceID, in.ContainerURL)
	if err != nil {
		return err
	}

	dest := in.destination(blobClient, containerName)

	if err = backupPolicies(fdPolicies, dest); err != nil {
		return err
	}

	return backupAppGWPolicies(appgwPolicies, dest)
}

// newBackupBlobClient builds the client used to upload backups to Azure
// Storage, along with the container to write into.
//
// A container url is sufficient on its own: it names both the storage account
// (its host) and the container (its path), and the session's Azure AD
// credential is used to authenticate — the caller's identity needs a blob data
// role on the account. Supplying a storage account resource id as well switches
// to shared key authentication, looking the account keys up through ARM, which
// is the option to reach for where no such role has been granted.
//
// Returns a nil client when no Azure Storage destination was requested, leaving
// the caller to write local files only.
func newBackupBlobClient(s *session.Session, storageAccountResourceID, containerURL string) (*azblob.Client, string, error) {
	funcName := helpers.GetFunctionName()

	if containerURL == "" {
		// a storage account alone does not say which container to write to
		if storageAccountResourceID != "" {
			return nil, "", fmt.Errorf("%s - a container url is required to back up to Azure Storage", funcName)
		}

		return nil, "", nil
	}

	parts, err := azblob.ParseURL(containerURL)
	if err != nil {
		return nil, "", fmt.Errorf("%s - failed to parse container url: %w", funcName, err)
	}

	if parts.ContainerName == "" {
		return nil, "", fmt.Errorf("%s - container url %s does not name a container", funcName, containerURL)
	}

	if storageAccountResourceID == "" {
		if s.ClientCredential == nil {
			if err = s.GetClientCredential(); err != nil {
				return nil, "", fmt.Errorf("%s - %w", funcName, err)
			}
		}

		// URLParts.Scheme is documented as "https://" but is returned bare, so
		// normalise rather than concatenating blind
		serviceURL := fmt.Sprintf("%s://%s/", strings.TrimSuffix(parts.Scheme, "://"), parts.Host)

		client, cerr := azblob.NewClient(serviceURL, s.ClientCredential, nil)
		if cerr != nil {
			return nil, "", fmt.Errorf("%s - failed to create blob client: %w", funcName, cerr)
		}

		return client, parts.ContainerName, nil
	}

	sari := config.ParseResourceID(storageAccountResourceID)

	storageAccountsClient, err := armstorage.NewAccountsClient(sari.SubscriptionID, s.ClientCredential, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%s - failed to create storage account client: %w", funcName, err)
	}

	sac, err := storageAccountsClient.ListKeys(context.Background(), sari.ResourceGroup, sari.Name, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%s - failed to list keys for storage account %s: %w", funcName, sari.Name, err)
	}

	if len(sac.Keys) == 0 {
		return nil, "", fmt.Errorf("%s - storage account %s returned no keys", funcName, sari.Name)
	}

	credential, err := azblob.NewSharedKeyCredential(sari.Name, *sac.Keys[0].Value)
	if err != nil {
		return nil, "", fmt.Errorf("%s - invalid credentials: %w", funcName, err)
	}

	client, err := azblob.NewClientWithSharedKeyCredential(
		fmt.Sprintf("https://%s.blob.core.windows.net/", sari.Name), credential, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%s - failed to create blob client: %w", funcName, err)
	}

	return client, parts.ContainerName, nil
}

// partitionRIDsByWAFType splits a mixed list of WAF resource ids into a Front
// Door slice and an Application Gateway slice. Anything that does not parse as
// AppGW falls into the FrontDoor slice — including resource id hashes which
// are still resolved through the FrontDoor lookup path.
func partitionRIDsByWAFType(rids []string) (fd, appgw []string) {
	for _, r := range rids {
		if WAFTypeFromResourceID(r) == WAFTypeAppGW {
			appgw = append(appgw, r)
			continue
		}

		fd = append(fd, r)
	}

	return fd, appgw
}

// BackupPolicy takes a WrappedPolicy as input and creates a json file that can later be restored
// BackupPolicy writes a Front Door policy, with its metadata, as a json file.
// BackupPolicy backs up a single Front Door policy. It and BackupAppGWPolicy
// are typed entry points onto backupWrapped, which cannot take a concrete type
// because the two wrapped policy types share no fields as far as Go is
// concerned.
func BackupPolicy(p *WrappedPolicy, dest BackupDestination) error {
	return backupWrapped(p, dest)
}

// backupSubject is what backupWrapped needs from either policy type. The two
// wrapped types share no fields as far as Go is concerned, so the metadata is
// reached through this rather than duplicating the function per type.
type backupSubject interface {
	// prepareForBackup stamps the backup date and, where it is not already
	// set, the default WAF type, returning what is needed to name and
	// describe the backup.
	prepareForBackup(now time.Time) backupInfo
}

// backupInfo is the metadata a backup is named and logged with.
type backupInfo struct {
	// kind names the policy type for the status line: "Policy" or "AppGW Policy".
	kind           string
	name           string
	subscriptionID string
	resourceGroup  string
}

func (p *WrappedPolicy) prepareForBackup(now time.Time) backupInfo {
	p.Date = now

	// tag every backup with its WAF type so restore can dispatch correctly.
	// Older files (without WAFType) are treated as FrontDoor when loading.
	if p.WAFType == "" {
		p.WAFType = WAFTypeFrontDoor
	}

	return backupInfo{
		kind:           "Policy",
		name:           p.Name,
		subscriptionID: p.SubscriptionID,
		resourceGroup:  p.ResourceGroup,
	}
}

func (p *WrappedAppGWPolicy) prepareForBackup(now time.Time) backupInfo {
	p.Date = now

	if p.WAFType == "" {
		p.WAFType = WAFTypeAppGW
	}

	return backupInfo{
		kind:           "AppGW Policy",
		name:           p.Name,
		subscriptionID: p.SubscriptionID,
		resourceGroup:  p.ResourceGroup,
	}
}

// backupDestination is where a backup is written: a local directory, a blob
// container, or both. These five travelled together as positional arguments
// through every backup function.
// BackupDestination is where a backup is written: a local directory, a blob
// container, or both. These five values travelled together through every
// backup function as positional arguments, which made call sites like
// (nil, "", true, false, dir) impossible to read at a glance.
type BackupDestination struct {
	// BlobClient is nil when no Azure Storage destination was requested.
	BlobClient    *azblob.Client
	ContainerName string
	// Path is the local directory to write to; empty skips the local copy.
	Path string
	// FailFast turns a per-policy failure into an error rather than a log line.
	FailFast bool
	Quiet    bool
}

// backupWrapped serialises a policy and writes it to the requested
// destinations. It backs both BackupPolicy and BackupAppGWPolicy, which
// previously held near-identical copies of it.
func backupWrapped(p backupSubject, dest BackupDestination) error {
	funcName := helpers.GetFunctionName()
	now := time.Now().UTC()
	info := p.prepareForBackup(now)

	var cwd string

	if !dest.Quiet {
		var oerr error

		cwd, oerr = os.Getwd()
		if oerr != nil {
			return oerr
		}

		printBackupStatus(fmt.Sprintf("backing up %s: %s", info.kind, info.name))
	}

	pj, err := json.MarshalIndent(p, "", "    ")
	if err != nil {
		if dest.FailFast {
			return err
		}

		logging.Errorf("failed to marshal %s %s: %s", info.kind, info.name, err)

		// nothing valid to write for this policy; skip it rather than
		// uploading empty content
		return nil
	}

	fName := fmt.Sprintf("%s+%s+%s+%s.json", info.subscriptionID, info.resourceGroup, info.name,
		now.Format("20060102150405"))

	// write locally first: the local copy is the cheaper and more reliable of
	// the two destinations, and must not be lost to an upload failure
	if dest.Path != "" {
		if err = writeBackupToFile(pj, cwd, fName, dest); err != nil {
			return fmt.Errorf("%s - %w", funcName, err)
		}
	}

	return uploadBackupToContainer(pj, fName, dest)
}

// printBackupStatus writes the progress line, trimming it when it exactly fills
// the terminal width.
func printBackupStatus(msg string) {
	statusOutput := PadToWidth(msg, " ", 0, true)

	width, _, err := terminal.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		// stdout is not a terminal (piped output, tests): use a default
		// width rather than failing the backup
		width = defaultTerminalWidth
	}

	if len(statusOutput) == width {
		fmt.Print(statusOutput[0:width-3] + "   \r")

		return
	}

	fmt.Print(statusOutput)
}

// uploadBackupToContainer uploads a serialised backup to blob storage. A nil
// client means no Azure Storage destination was requested, so there is nothing
// to do. Upload failures honour failFast, matching the rest of the backup path:
// the local copy has already been written by this point.
func uploadBackupToContainer(pj []byte, fName string, dest BackupDestination) error {
	if dest.BlobClient == nil {
		return nil
	}

	if !dest.Quiet {
		logging.Infof("uploading file with blob name: %s\n", fName)
	}

	_, err := dest.BlobClient.UploadBuffer(context.Background(), dest.ContainerName, fName, pj, &azblob.UploadBufferOptions{
		BlockSize:   blockBlobUploadBlockSize,
		Concurrency: blockBlobParallelism,
	})
	if err != nil {
		if dest.FailFast {
			return fmt.Errorf("%s - failed to upload %s: %w", helpers.GetFunctionName(), fName, err)
		}

		logging.Errorf("failed to upload %s to container %s: %s", fName, dest.ContainerName, err)
	}

	return nil
}

func writeBackupToFile(pj []byte, cwd, fName string, dest BackupDestination) (err error) {
	funcName := helpers.GetFunctionName()

	fp := filepath.Join(dest.Path, fName)
	// #nosec
	f, err := os.Create(fp)
	if err != nil {
		return fmt.Errorf("%s - failed to create file: %s with error: %s", funcName, fp, err.Error())
	}

	_, err = f.Write(pj)
	if err != nil {
		_ = f.Close()

		return
	}

	_ = f.Close()

	if !dest.Quiet {
		op := filepath.Clean(fp)
		if strings.HasPrefix(op, cwd) {
			op, err = filepath.Rel(cwd, op)
			if err != nil {
				return fmt.Errorf("%s - %s", funcName, err.Error())
			}

			op = "./" + op
		}

		logging.Infof("backup written to: %s", op)
	}

	return
}

// backupPolicies accepts a list of WrappedPolicys and calls BackupPolicy with each
func backupPolicies(policies []WrappedPolicy, dest BackupDestination) (err error) {
	for x := range policies {
		// return only on error: previously this returned unconditionally under
		// fail-fast, silently skipping every policy after the first
		if err = BackupPolicy(&policies[x], dest); err != nil {
			if dest.FailFast {
				return err
			}

			logging.Error(err)
		}
	}

	return nil
}

// BackupAppGWPolicy is the AppGW analogue of BackupPolicy. It writes the
// supplied WrappedAppGWPolicy as JSON to disk and/or Azure Blob Storage.
// BackupAppGWPolicy is the Application Gateway equivalent of BackupPolicy.
// BackupAppGWPolicy backs up a single Application Gateway policy.
func BackupAppGWPolicy(p *WrappedAppGWPolicy, dest BackupDestination) error {
	return backupWrapped(p, dest)
}

func backupAppGWPolicies(policies []WrappedAppGWPolicy, dest BackupDestination) error {
	for x := range policies {
		if err := BackupAppGWPolicy(&policies[x], dest); err != nil {
			if dest.FailFast {
				return err
			}

			logging.Error(err)
		}
	}

	return nil
}

func PadToWidth(input, char string, inputLengthOverride int, trimToWidth bool) string {
	lines := strings.Split(strings.TrimSuffix(input, "\n"), "\n")

	width, _, err := terminal.GetSize(int(os.Stdout.Fd()))
	if err != nil || width == -1 {
		width = defaultTerminalWidth
	}

	for i, line := range lines {
		length := len(line)
		if inputLengthOverride > 0 {
			length = inputLengthOverride
		}

		if length >= width {
			if trimToWidth {
				return line[:width]
			}

			return input
		}

		padding := width - length
		if inputLengthOverride != 0 {
			padding = width - inputLengthOverride
		}

		suffix := "\n"
		if i == len(lines)-1 {
			suffix = "\r"
		}

		lines[i] = fmt.Sprintf("%s%s%s", line, strings.Repeat(char, padding), suffix)
	}

	return strings.Join(lines, "")
}
