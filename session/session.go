package session

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/jonhadfield/azwaf/helpers"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
)

const (
	WorkingRelPath = ".azwaf"
	BackupsRelPath = "backups"
	CacheRelPath   = "cache"
	CacheFile      = "cache.db"
)

type Session struct {
	ClientCredential                    azcore.TokenCredential
	FrontDoorPoliciesClients            map[string]*armfrontdoor.PoliciesClient
	FrontDoorsClients                   map[string]*armfrontdoor.FrontDoorsClient
	FrontDoorsManagedRuleSetsClients    map[string]*armfrontdoor.ManagedRuleSetsClient
	FrontDoorsManagedRuleSetDefinitions []*armfrontdoor.ManagedRuleSetDefinition
	ResourcesClients                    map[string]*armresources.Client
	WorkingDir                          string
	BackupsDir                          string
	CacheDir                            string
	CachePath                           string
	Cache                               *buntdb.DB
	AppVersion                          string
}

func createDirectory(path string) error {
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	return nil
}

func (s *Session) InitialiseFilePaths() error {
	funcName := helpers.GetFunctionName()

	// attempt to use home directory as working directory for cache and auto-backups
	workingRoot, herr := homedir.Dir()
	if herr != nil {
		logrus.Warnf("%s | failed to get home directory: %s", funcName, herr)
	}

	// if home directory can't be used, use current path
	if workingRoot == "" {
		var gerr error

		workingRoot, gerr = os.Getwd()
		if gerr != nil {
			return fmt.Errorf("failed to set working directory: %s", gerr.Error())
		}
	}

	workingDir := filepath.Join(workingRoot, WorkingRelPath)
	if err := createDirectory(workingDir); err != nil {
		return err
	}

	s.WorkingDir = workingDir
	logrus.Debugf("%s | working directory set to %s", funcName, s.WorkingDir)

	cacheDir := filepath.Join(workingDir, CacheRelPath)
	if err := createDirectory(cacheDir); err != nil {
		return err
	}

	s.CacheDir = cacheDir

	backupsDir := filepath.Join(workingDir, BackupsRelPath)
	if err := createDirectory(backupsDir); err != nil {
		return err
	}

	s.BackupsDir = backupsDir

	return nil
}

func New() *Session {
	s := &Session{}

	if err := s.InitialiseFilePaths(); err != nil {
		logrus.Fatalf("%s | failed to initialise paths: %s", helpers.GetFunctionName(), err.Error())
	}

	return s
}

func (s *Session) InitialiseCache() {
	funcName := helpers.GetFunctionName()

	// if we don't have a session or we do, and the cache is initialised, then return it
	if s == nil {
		panic("%s called with null session")
	}

	home, err := homedir.Dir()
	if err != nil {
		logrus.Errorf("%s - failed to get home directory: %s", funcName, err)
	}

	appDir := filepath.Join(home, WorkingRelPath)

	if _, err = os.Stat(appDir); os.IsNotExist(err) {
		if err = os.Mkdir(appDir, os.ModePerm); err != nil {
			logrus.Errorf("%s - failed to create application directory: %s", funcName, err)

			return
		}
	}

	if s.CachePath == "" {
		s.CachePath = filepath.Join(appDir, CacheFile)
	}

	cacheDB, err := buntdb.Open(s.CachePath)
	if err != nil {
		logrus.Errorf("%s - failed to open cache: %s", funcName, err)
	}

	s.Cache = cacheDB
}

// GetFrontDoorsClient creates a front doors client for the given Subscription and stores it in the provided session.
// If an Authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *Session) GetFrontDoorsClient(subID string) (c armfrontdoor.FrontDoorsClient, err error) {
	if s.FrontDoorsClients == nil {
		s.FrontDoorsClients = make(map[string]*armfrontdoor.FrontDoorsClient)
	}

	if s.FrontDoorsClients[subID] != nil {
		logrus.Debugf("re-using front doors client for Subscription: %s", subID)

		return *s.FrontDoorsClients[subID], nil
	}

	if s.ClientCredential == nil {
		err = s.GetClientCredential()
		if err != nil {
			return
		}
	}

	logrus.Debugf("creating front doors client")

	frontDoorsClient, merr := armfrontdoor.NewFrontDoorsClient(subID, s.ClientCredential, nil)
	if merr != nil {
		return c, fmt.Errorf(merr.Error(), helpers.GetFunctionName())
	}

	s.FrontDoorsClients[subID] = frontDoorsClient

	return
}

func (s *Session) GetClientCredential() error {
	funcName := helpers.GetFunctionName()
	startTime := time.Now()

	// Check if we already have a credential
	if s.ClientCredential != nil {
		logrus.Infof("%s | Reusing existing credential", funcName)
		return nil
	}

	logrus.Infof("%s | Starting Azure credential retrieval", funcName)

	// Check if we're running in Azure or if managed identity is explicitly requested
	// Allow forcing managed identity with AZURE_USE_MANAGED_IDENTITY=true
	forceManagedIdentity := os.Getenv("AZURE_USE_MANAGED_IDENTITY") == "true"
	
	inAzure := forceManagedIdentity ||
		os.Getenv("WEBSITE_INSTANCE_ID") != "" || // Azure App Service
		os.Getenv("IDENTITY_ENDPOINT") != "" || // Azure Functions/Container Instances  
		os.Getenv("IMDS_ENDPOINT") != "" || // Azure VM/VMSS with specific endpoint
		os.Getenv("MSI_ENDPOINT") != "" || // Legacy MSI endpoint
		os.Getenv("ACC_CLOUD") == "AZURE" || // Azure Cloud Shell
		os.Getenv("AZURESUBSCRIPTION_CLIENT_ID") != "" || // Azure DevOps
		os.Getenv("AZURE_RESOURCE_GROUP") != "" // Common Azure environment indicator
	
	// Additional check: see if we can detect Azure VM by checking for Azure-specific paths
	if !inAzure {
		// Check if we're on an Azure VM by looking for Azure agent
		if _, err := os.Stat("/var/lib/waagent"); err == nil {
			inAzure = true
			logrus.Debugf("%s | Detected Azure VM via waagent directory", funcName)
		}
	}

	// Try environment credential first (fastest - reads from env vars)
	envStartTime := time.Now()
	logrus.Infof("%s | Trying environment credential first...", funcName)
	envCred, envErr := azidentity.NewEnvironmentCredential(nil)
	envDuration := time.Since(envStartTime)
	
	if envErr == nil {
		logrus.Infof("%s | Environment credential created in %v", funcName, envDuration)
		s.ClientCredential = envCred
		s.InitialiseCache()
		totalDuration := time.Since(startTime)
		logrus.Infof("%s | Successfully retrieved credential via environment (total: %v)", funcName, totalDuration)
		return nil
	}
	logrus.Debugf("%s | Environment credential not available after %v: %v", funcName, envDuration, envErr)

	// Only try managed identity if we detect we're running in Azure
	if inAzure {
		// Try managed identity (second fastest)
		miStartTime := time.Now()
		if forceManagedIdentity {
			logrus.Infof("%s | AZURE_USE_MANAGED_IDENTITY=true, forcing managed identity credential...", funcName)
		} else {
			logrus.Infof("%s | Detected Azure environment, trying managed identity credential...", funcName)
		}
		miCred, miErr := azidentity.NewManagedIdentityCredential(nil)
		miDuration := time.Since(miStartTime)
		
		if miErr == nil {
			logrus.Infof("%s | Managed identity credential created in %v", funcName, miDuration)
			s.ClientCredential = miCred
			s.InitialiseCache()
			totalDuration := time.Since(startTime)
			logrus.Infof("%s | Successfully retrieved credential via managed identity (total: %v)", funcName, totalDuration)
			return nil
		}
		logrus.Errorf("%s | Managed identity failed after %v: %v", funcName, miDuration, miErr)
	} else {
		logrus.Infof("%s | Azure environment not detected, skipping managed identity credential", funcName)
		logrus.Debugf("%s | To force managed identity, set AZURE_USE_MANAGED_IDENTITY=true", funcName)
	}

	// Check if Azure CLI is available before trying it
	azPath, azErr := exec.LookPath("az")
	if azErr == nil {
		// Try Azure CLI credential
		cliStartTime := time.Now()
		logrus.Infof("%s | Azure CLI binary found at %s, trying Azure CLI credential...", funcName, azPath)
		cliCred, cliErr := azidentity.NewAzureCLICredential(nil)
		cliDuration := time.Since(cliStartTime)
		
		if cliErr == nil {
			logrus.Infof("%s | Azure CLI credential created in %v", funcName, cliDuration)
			s.ClientCredential = cliCred
			s.InitialiseCache()
			totalDuration := time.Since(startTime)
			logrus.Infof("%s | Successfully retrieved credential via Azure CLI (total: %v)", funcName, totalDuration)
			return nil
		}
		logrus.Errorf("%s | Azure CLI credential failed after %v: %v", funcName, cliDuration, cliErr)
	} else {
		logrus.Infof("%s | Azure CLI binary not found on PATH (error: %v), skipping Azure CLI credential", funcName, azErr)
	}

	// We've tried all the credential methods individually
	// Don't use DefaultAzureCredential as it would retry managed identity and cause hangs
	totalDuration := time.Since(startTime)
	logrus.Errorf("%s | All credential methods failed after %v", funcName, totalDuration)
	
	errorMsg := fmt.Sprintf("%s | No valid Azure credentials found after %v. Please authenticate using one of:\n", funcName, totalDuration)
	errorMsg += "  1. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)\n"
	errorMsg += "  2. Azure CLI (run 'az login')\n"
	if inAzure {
		errorMsg += "  3. Managed Identity (when running in Azure)\n"
	}
	
	return fmt.Errorf(errorMsg)
}
