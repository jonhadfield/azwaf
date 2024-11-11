package session

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/sirupsen/logrus"
)

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}

// GetResourcesClient creates a new resources client instance and stores it in the provided session.
// If an authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *Session) GetResourcesClient(subID string) (err error) {
	if s.ResourcesClients == nil {
		s.ResourcesClients = make(map[string]*resources.Client)
	}

	if s.ResourcesClients[subID] != nil {
		logrus.Debugf("re-using resources client for subscription: %s", subID)

		return nil
	}

	logrus.Debugf("creating resources client for subscription: %s", subID)

	c := resources.NewClient(subID)
	
	err = s.GetAuthorizer()
	if err != nil {
		logrus.Error(err.Error())
		return
	}

	s.ResourcesClients[subID] = &c
	s.ResourcesClients[subID].Authorizer = *s.Authorizer

	return
}

func (s *Session) GetFrontDoorPoliciesClient(subID string) (err error) {
	funcName := GetFunctionName()

	if s == nil {
		return errors.New("session is nil")
	}

	if s.FrontDoorPoliciesClients == nil {
		s.FrontDoorPoliciesClients = make(map[string]*armfrontdoor.PoliciesClient)
	}

	if s.FrontDoorPoliciesClients[subID] != nil {
		logrus.Debugf("%s | re-using arm front door policies client for subscription: %s", funcName, subID)

		return nil
	}

	logrus.Debugf("%s | creating new policies client for subscription: %s", funcName, subID)

	if s.Authorizer == nil {
		err = s.GetAuthorizer()
		if err != nil {
			return
		}
	}

	if s.Credential == nil {
		err = s.GetCredential()
		if err != nil {
			return
		}
	}

	frontDoorPoliciesClient, merr := armfrontdoor.NewPoliciesClient(subID, s.Credential, nil)
	if merr != nil {
		return fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	s.FrontDoorPoliciesClients[subID] = frontDoorPoliciesClient

	return
}

func (s *Session) GetManagedRuleSetsClient(subID string) (err error) {
	funcName := GetFunctionName()

	if subID == "" {
		return fmt.Errorf("%s - subscription id is mandatory", funcName)
	}

	if s.FrontDoorsManagedRuleSetsClients == nil {
		s.FrontDoorsManagedRuleSetsClients = make(map[string]*armfrontdoor.ManagedRuleSetsClient)
	}

	if s.FrontDoorsManagedRuleSetsClients[subID] != nil {
		logrus.Debugf("re-using arm front door rules sets client for subscription: %s", subID)

		return nil
	}

	logrus.Debugf("creating arm front door managed rule sets client for subscription: %s", subID)

	if s.Authorizer == nil {
		err = s.GetAuthorizer()
		if err != nil {
			return
		}
	}

	if s.GetCredential() != nil {
		return
	}

	logrus.Debugf("creating new manage rule sets client for sub: %s", subID)

	frontDoorManagedRuleSetsClient, merr := armfrontdoor.NewManagedRuleSetsClient(subID, s.Credential, nil)
	if merr != nil {
		return fmt.Errorf(merr.Error(), GetFunctionName())
	}

	s.FrontDoorsManagedRuleSetsClients[subID] = frontDoorManagedRuleSetsClient

	return
}
