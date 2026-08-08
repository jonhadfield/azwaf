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

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	terminal "golang.org/x/term"
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
			GetFunctionName())
	}

	if err := validateSubscriptionID(in.SubscriptionID); err != nil {
		return err
	}

	return nil
}

// BackupPolicies retrieves policies within a subscription and writes them, with meta-data, to individual json files.
// Both Azure Front Door and Azure Application Gateway WAF policies are
// supported; the resource type embedded in each resource id determines which
// API the policy is fetched from. When no resource ids are supplied, every WAF
// policy of either type within the subscription is backed up.
func BackupPolicies(in *BackupPoliciesInput) error {
	funcName := GetFunctionName()

	if err := in.Validate(); err != nil {
		return err
	}

	s := in.Session
	if s == nil {
		s = session.New()
	}

	// fail if only one of the storage account destination required parameters been defined
	if (in.StorageAccountResourceID != "" && in.ContainerURL == "") || (in.StorageAccountResourceID == "" && in.ContainerURL != "") {
		return fmt.Errorf("%s - both storage account resource id and container url are required for backups to Azure Storage",
			funcName)
	}

	// fail if neither path nor storage account details are provided
	if in.StorageAccountResourceID == "" && in.Path == "" {
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

	logrus.Debugf("%s | retrieved %d FrontDoor and %d AppGW policies", funcName, len(fdPolicies), len(appgwPolicies))

	var blobClient *azblob.Client
	var containerName string

	if in.StorageAccountResourceID != "" {
		sari := config.ParseResourceID(in.StorageAccountResourceID)
		var storageAccountsClient *armstorage.AccountsClient
		storageAccountsClient, err = armstorage.NewAccountsClient(sari.SubscriptionID, s.ClientCredential, nil)
		if err != nil {
			return fmt.Errorf("failed to create storage account client - %s", err.Error())
		}

		ctx := context.Background()

		var sac armstorage.AccountsClientListKeysResponse

		sac, oerr := storageAccountsClient.ListKeys(ctx, sari.ResourceGroup, sari.Name, nil)
		if oerr != nil {
			return fmt.Errorf("failed to list keys for storage account %s - %s", sari.Name, oerr.Error())
		}

		b := sac.Keys[0]

		credential, oerr := azblob.NewSharedKeyCredential(sari.Name, *b.Value)
		if oerr != nil {
			return fmt.Errorf("invalid credentials with error: %s", oerr.Error())
		}

		// Modern SDK: Create service client and extract container name from URL
		// ContainerURL format: https://storageaccount.blob.core.windows.net/containername
		serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", sari.Name)
		blobClient, oerr = azblob.NewClientWithSharedKeyCredential(serviceURL, credential, nil)
		if oerr != nil {
			return fmt.Errorf("failed to create blob client: %s", oerr.Error())
		}

		// Extract container name from ContainerURL
		// Parse the URL and get the path component (should be /containername)
		parts, oerr := azblob.ParseURL(in.ContainerURL)
		if oerr != nil {
			return fmt.Errorf("failed to parse container URL: %s", oerr.Error())
		}
		containerName = parts.ContainerName
	}

	if err = backupPolicies(fdPolicies, blobClient, containerName, in.FailFast, in.Quiet, in.Path); err != nil {
		return err
	}

	return backupAppGWPolicies(appgwPolicies, blobClient, containerName, in.FailFast, in.Quiet, in.Path)
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
func BackupPolicy(p *WrappedPolicy, blobClient *azblob.Client, containerName string, failFast, quiet bool, path string) (err error) {
	funcName := GetFunctionName()
	now := time.Now().UTC()
	dateString := now.UTC().Format("20060102150405")
	p.Date = now

	// tag every backup with its WAF type so restore can dispatch correctly.
	// Older files (without WAFType) are treated as FrontDoor when loading.
	if p.WAFType == "" {
		p.WAFType = WAFTypeFrontDoor
	}

	var cwd string

	if !quiet {
		var oerr error

		cwd, oerr = os.Getwd()
		if oerr != nil {
			return oerr
		}

		msg := fmt.Sprintf("backing up Policy: %s", p.Name)
		statusOutput := PadToWidth(msg, " ", 0, true)
		fd := int(os.Stdout.Fd())

		width, _, terr := terminal.GetSize(fd)
		if terr != nil {
			// stdout is not a terminal (piped output, tests): use a default
			// width rather than failing the backup
			width = defaultTerminalWidth
		}

		if len(statusOutput) == width {
			fmt.Print(statusOutput[0:width-3] + "   \r")
		} else {
			fmt.Print(statusOutput)
		}
	}

	pj, oerr := json.MarshalIndent(p, "", "    ")
	if oerr != nil {
		if failFast {
			return oerr
		}

		logrus.Errorf("failed to marshal policy %s: %s", p.Name, oerr)

		// nothing valid to write for this policy; skip it rather than
		// uploading empty content
		return nil
	}

	fName := fmt.Sprintf("%s+%s+%s+%s.json", p.SubscriptionID, p.ResourceGroup, p.Name, dateString)

	// write to storage account
	if blobClient != nil {
		ctx := context.Background()

		if !quiet {
			logrus.Infof("uploading file with blob name: %s\n", fName)
		}

		// Modern SDK: Upload blob directly using the service client with container name and blob name
		_, oerr = blobClient.UploadBuffer(ctx, containerName, fName, pj, &azblob.UploadBufferOptions{
			BlockSize:   blockBlobUploadBlockSize,
			Concurrency: blockBlobParallelism,
		})
		if oerr != nil {
			return oerr
		}
	}

	if path != "" {
		err = writeBackupToFile(pj, cwd, fName, quiet, path)
		if err != nil {
			return fmt.Errorf("%s - %w", funcName, err)
		}
	}

	return
}

func writeBackupToFile(pj []byte, cwd, fName string, quiet bool, path string) (err error) {
	funcName := GetFunctionName()

	fp := filepath.Join(path, fName)
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

	if !quiet {
		op := filepath.Clean(fp)
		if strings.HasPrefix(op, cwd) {
			op, err = filepath.Rel(cwd, op)
			if err != nil {
				return fmt.Errorf("%s - %s", funcName, err.Error())
			}

			op = "./" + op
		}

		logrus.Infof("backup written to: %s", op)
	}

	return
}

// backupPolicies accepts a list of WrappedPolicys and calls BackupPolicy with each
func backupPolicies(policies []WrappedPolicy, blobClient *azblob.Client, containerName string, failFast, quiet bool, path string) (err error) {
	for x := range policies {
		// return only on error: previously this returned unconditionally under
		// fail-fast, silently skipping every policy after the first
		if err = BackupPolicy(&policies[x], blobClient, containerName, failFast, quiet, path); err != nil {
			if failFast {
				return err
			}

			logrus.Error(err)
		}
	}

	return nil
}

// BackupAppGWPolicy is the AppGW analogue of BackupPolicy. It writes the
// supplied WrappedAppGWPolicy as JSON to disk and/or Azure Blob Storage.
func BackupAppGWPolicy(p *WrappedAppGWPolicy, blobClient *azblob.Client, containerName string, failFast, quiet bool, path string) error {
	funcName := GetFunctionName()
	now := time.Now().UTC()
	dateString := now.UTC().Format("20060102150405")
	p.Date = now

	if p.WAFType == "" {
		p.WAFType = WAFTypeAppGW
	}

	var cwd string

	if !quiet {
		var oerr error

		cwd, oerr = os.Getwd()
		if oerr != nil {
			return oerr
		}

		msg := fmt.Sprintf("backing up AppGW Policy: %s", p.Name)
		statusOutput := PadToWidth(msg, " ", 0, true)
		fd := int(os.Stdout.Fd())

		width, _, terr := terminal.GetSize(fd)
		if terr != nil {
			// stdout is not a terminal (piped output, tests): use a default
			// width rather than failing the backup
			width = defaultTerminalWidth
		}

		if len(statusOutput) == width {
			fmt.Print(statusOutput[0:width-3] + "   \r")
		} else {
			fmt.Print(statusOutput)
		}
	}

	pj, oerr := json.MarshalIndent(p, "", "    ")
	if oerr != nil {
		if failFast {
			return oerr
		}

		logrus.Errorf("failed to marshal AppGW policy %s: %s", p.Name, oerr)

		// nothing valid to write for this policy; skip it rather than
		// uploading empty content
		return nil
	}

	fName := fmt.Sprintf("%s+%s+%s+%s.json", p.SubscriptionID, p.ResourceGroup, p.Name, dateString)

	if blobClient != nil {
		ctx := context.Background()

		if !quiet {
			logrus.Infof("uploading file with blob name: %s\n", fName)
		}

		if _, oerr = blobClient.UploadBuffer(ctx, containerName, fName, pj, &azblob.UploadBufferOptions{
			BlockSize:   blockBlobUploadBlockSize,
			Concurrency: blockBlobParallelism,
		}); oerr != nil {
			return oerr
		}
	}

	if path != "" {
		if err := writeBackupToFile(pj, cwd, fName, quiet, path); err != nil {
			return fmt.Errorf("%s - %w", funcName, err)
		}
	}

	return nil
}

func backupAppGWPolicies(policies []WrappedAppGWPolicy, blobClient *azblob.Client, containerName string, failFast, quiet bool, path string) error {
	for x := range policies {
		if err := BackupAppGWPolicy(&policies[x], blobClient, containerName, failFast, quiet, path); err != nil {
			if failFast {
				return err
			}

			logrus.Error(err)
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
