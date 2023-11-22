package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jonhadfield/azwaf/config"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/Azure/azure-storage-blob-go/azblob"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	terminal "golang.org/x/term"
)

// BackupPoliciesInput are the arguments provided to the BackupPolicies function.
type BackupPoliciesInput struct {
	BaseCLIInput
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

// BackupPolicies retrieves policies within a subscription and writes them, with meta-data, to individual json files
func BackupPolicies(in *BackupPoliciesInput) error {
	funcName := GetFunctionName()

	if err := in.Validate(); err != nil {
		return err
	}

	s := session.New()

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

	o, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    in.SubscriptionID,
		AppVersion:        in.AppVersion,
		FilterResourceIDs: in.RIDs,
		Config:            in.ConfigPath,
	})
	if err != nil {
		return err
	}

	logrus.Debugf("%s | retrieved %d policies", funcName, len(o.Policies))

	var containerURL azblob.ContainerURL

	if in.StorageAccountResourceID != "" {
		sari := config.ParseResourceID(in.StorageAccountResourceID)
		storageAccountsClient := storage.NewAccountsClient(sari.SubscriptionID)
		storageAccountsClient.Authorizer = *s.Authorizer
		ctx := context.Background()

		var sac storage.AccountListKeysResult

		sac, oerr := storageAccountsClient.ListKeys(ctx, sari.ResourceGroup, sari.Name, "")
		if oerr != nil {
			return fmt.Errorf("failed to list keys for storage account %s - %s", sari.Name, oerr.Error())
		}

		keys := *sac.Keys
		b := keys[0]

		credential, oerr := azblob.NewSharedKeyCredential(sari.Name, *b.Value)
		if oerr != nil {
			return fmt.Errorf("invalid credentials with error: %s", oerr.Error())
		}

		p := azblob.NewPipeline(credential, azblob.PipelineOptions{})

		var cu *url.URL

		cu, oerr = url.Parse(in.ContainerURL)
		if oerr != nil {
			return oerr
		}

		containerURL = azblob.NewContainerURL(*cu, p)
	}

	return backupPolicies(o.Policies, &containerURL, in.FailFast, in.Quiet, in.Path)
}

// BackupPolicy takes a WrappedPolicy as input and creates a json file that can later be restored
func BackupPolicy(p *WrappedPolicy, containerURL *azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	funcName := GetFunctionName()
	now := time.Now().UTC()
	dateString := now.UTC().Format("20060102150405")
	p.Date = now

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
			return fmt.Errorf(terr.Error(), funcName)
		}

		if len(statusOutput) == width {
			fmt.Printf(statusOutput[0:width-3] + "   \r")
		} else {
			fmt.Print(statusOutput)
		}
	}

	pj, oerr := json.MarshalIndent(p, "", "    ")
	if oerr != nil {
		if failFast {
			return oerr
		}

		logrus.Error(err)
	}

	fName := fmt.Sprintf("%s+%s+%s+%s.json", p.SubscriptionID, p.ResourceGroup, p.Name, dateString)

	// write to storage account
	if containerURL != nil && containerURL.String() != "" {
		ctx := context.Background()

		blobURL := containerURL.NewBlockBlobURL(fName)

		if !quiet {
			logrus.Infof("uploading file with blob name: %s\n", fName)
		}

		_, oerr = azblob.UploadBufferToBlockBlob(ctx, pj, blobURL, azblob.UploadToBlockBlobOptions{
			BlockSize:   4 * 1024 * 1024,
			Parallelism: 16,
		})
		if oerr != nil {
			return oerr
		}
	}

	if path != "" {
		err = writeBackupToFile(pj, cwd, fName, quiet, path)
		if err != nil {
			return fmt.Errorf(err.Error(), funcName)
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
func backupPolicies(policies []WrappedPolicy, containerURL *azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	for x := range policies {
		err = BackupPolicy(&policies[x], containerURL, failFast, quiet, path)

		if failFast {
			return
		}
	}

	return
}

func PadToWidth(input, char string, inputLengthOverride int, trimToWidth bool) (output string) {
	var lines []string

	var newLines []string

	if strings.Contains(input, "\n") {
		lines = strings.Split(input, "\n")
	} else {
		lines = []string{input}
	}

	var paddingSize int

	for i, line := range lines {
		fd := int(os.Stdout.Fd())

		width, _, err := terminal.GetSize(fd)
		if err != nil {
			logrus.Fatalf("failed to get terminal width - %s", err.Error())
		}

		if width == -1 {
			width = 80
		}
		// No padding for a line that already meets or exceeds console width
		var length int
		if inputLengthOverride > 0 {
			length = inputLengthOverride
		} else {
			length = len(line)
		}

		switch {
		case length >= width:
			if trimToWidth {
				output = line[0:width]
			} else {
				output = input
			}

			return
		case i == len(lines)-1:
			if inputLengthOverride != 0 {
				paddingSize = width - inputLengthOverride
			} else {
				paddingSize = width - len(line)
			}

			if paddingSize >= 1 {
				newLines = append(newLines, fmt.Sprintf("%s%s\r", line, strings.Repeat(char, paddingSize)))
			} else {
				newLines = append(newLines, fmt.Sprintf("%s\r", line))
			}
		default:
			var suffix string

			newLines = append(newLines, fmt.Sprintf("%s%s%s\n", line, strings.Repeat(char, paddingSize), suffix))
		}
	}

	output = strings.Join(newLines, "")

	return
}
