package session

import (
	"fmt"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/go-autorest/autorest"

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
	Authorizer                          *autorest.Authorizer
	Credential                          azcore.TokenCredential
	FrontDoorPoliciesClients            map[string]*armfrontdoor.PoliciesClient
	FrontDoorsClients                   map[string]*armfrontdoor.FrontDoorsClient
	FrontDoorsManagedRuleSetsClients    map[string]*armfrontdoor.ManagedRuleSetsClient
	FrontDoorsManagedRuleSetDefinitions []*armfrontdoor.ManagedRuleSetDefinition
	ResourcesClients                    map[string]*resources.Client
	WorkingDir                          string
	BackupsDir                          string
	CacheDir                            string
	CachePath                           string
	Cache                               *buntdb.DB
	AppVersion                          string
}

func createDirectory(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err = os.Mkdir(path, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create backups directory %s: %s",
				path, err.Error())
		}
	}

	return nil
}

func (s *Session) InitialiseFilePaths() error {
	funcName := GetFunctionName()

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
		logrus.Fatalf("%s | failed to initialise paths: %s", GetFunctionName(), err.Error())
	}

	return s
}

func (s *Session) InitialiseCache() {
	funcName := GetFunctionName()

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

	if s.Authorizer == nil {
		err = s.GetAuthorizer()
		if err != nil {
			return
		}
	}

	err = s.GetCredential()
	if err != nil {
		return
	}

	logrus.Debugf("creating front doors client")

	frontDoorsClient, merr := armfrontdoor.NewFrontDoorsClient(subID, s.Credential, nil)
	if merr != nil {
		return c, fmt.Errorf(merr.Error(), GetFunctionName())
	}

	s.FrontDoorsClients[subID] = frontDoorsClient

	return
}

func (s *Session) GetCredential() error {
	funcName := GetFunctionName()

	if s.Credential != nil {
		logrus.Debug("returning existing credential from session")

		return nil
	}

	// try from environment first
	cred, err := azidentity.NewEnvironmentCredential(nil)
	if err != nil {
		logrus.Debugf("%s | failed to get credential from environment", funcName)
	}

	if cred != nil {
		s.Credential = cred

		logrus.Debugf("%s | retrieved credential from environment", funcName)

		return nil
	}

	s.Credential, err = azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return err
	}

	if s.Credential != nil {
		logrus.Debugf("%s | retrieved default credential", funcName)

		return nil
	}

	s.Credential, err = azidentity.NewAzureCLICredential(nil)
	if err != nil {
		logrus.Debugf("failed to get new cli credential")
	}

	return fmt.Errorf(err.Error(), funcName)
}

func (s *Session) GetAuthorizer() error {
	funcName := GetFunctionName()

	logrus.Debugf("authenticating with Azure")

	if s.Authorizer != nil {
		return nil
	}

	// try from environment first
	a, err := auth.NewAuthorizerFromEnvironment()
	if err == nil {
		s.Authorizer = &a

		logrus.Debugf("%s | retrieved Authorizer from environment", funcName)

		s.InitialiseCache()

		logrus.Debug("authenticated with environment")

		return nil
	}

	logrus.Debugf("%s | failed to create authorizer from environment: %s", funcName, err.Error())

	a, err = auth.NewAuthorizerFromCLI()
	if err == nil {
		s.Authorizer = &a

		logrus.Debugf("%s | retrieved Authorizer from cli", funcName)

		// initialize cache
		s.InitialiseCache()

		logrus.Debug("authenticated with cli")

		return nil
	}

	if strings.Contains(err.Error(), "CERTIFICATE_VERIFY_FAILED") {
		return fmt.Errorf("%s - ssl handshake failed", funcName)
	}

	return fmt.Errorf("%s | authorization failed: %s", err.Error(), funcName)
}
