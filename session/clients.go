package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/helpers"
	"github.com/sirupsen/logrus"
)

// GetResourcesClient creates a new resources client instance and stores it in the provided session.
// If an authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *Session) GetResourcesClient(subID string) (err error) {
	if s.ResourcesClients == nil {
		s.ResourcesClients = make(map[string]*armresources.Client)
	}

	if s.ResourcesClients[subID] != nil {
		logrus.Debugf("re-using resources client for subscription: %s", subID)

		return nil
	}

	logrus.Debugf("creating resources client for subscription: %s", subID)

	if s.ClientCredential == nil {
		err = s.GetClientCredential()
		if err != nil {
			return
		}
	}

	c, err := armresources.NewClient(subID, s.ClientCredential, nil)
	if err != nil {
		return fmt.Errorf(err.Error(), helpers.GetFunctionName())
	}

	s.ResourcesClients[subID] = c

	return
}

func (s *Session) GetFrontDoorPoliciesClient(subID string) (err error) {
	funcName := helpers.GetFunctionName()
	startTime := time.Now()

	logrus.Infof("%s | Starting GetFrontDoorPoliciesClient for subscription: %s", funcName, subID)

	if s == nil {
		return errors.New("session is nil")
	}

	if s.FrontDoorPoliciesClients == nil {
		s.FrontDoorPoliciesClients = make(map[string]*armfrontdoor.PoliciesClient)
	}

	if s.FrontDoorPoliciesClients[subID] != nil {
		logrus.Infof("%s | Re-using existing client (took: %v)", funcName, time.Since(startTime))
		return nil
	}

	logrus.Infof("%s | Creating new policies client for subscription: %s", funcName, subID)

	if s.ClientCredential == nil {
		credStartTime := time.Now()
		logrus.Infof("%s | Getting client credentials...", funcName)
		err = s.GetClientCredential()
		credDuration := time.Since(credStartTime)
		logrus.Infof("%s | Client credential retrieval took: %v", funcName, credDuration)
		if err != nil {
			logrus.Errorf("%s | Failed to get client credentials: %v", funcName, err)
			return
		}
	}

	clientCreateStartTime := time.Now()
	logrus.Infof("%s | Creating Azure Frontdoor client with optimized settings...", funcName)
	
	// Create client options with custom retry and timeout settings
	clientOptions := &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Retry: policy.RetryOptions{
				MaxRetries:    3,
				RetryDelay:    time.Second,
				MaxRetryDelay: time.Second * 30,
			},
			Telemetry: policy.TelemetryOptions{
				ApplicationID: "azwaf",
			},
		},
	}
	
	frontDoorPoliciesClient, merr := armfrontdoor.NewPoliciesClient(subID, s.ClientCredential, clientOptions)
	clientCreateDuration := time.Since(clientCreateStartTime)
	
	if merr != nil {
		logrus.Errorf("%s | Failed to create client after %v: %s", funcName, clientCreateDuration, merr.Error())
		return fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	s.FrontDoorPoliciesClients[subID] = frontDoorPoliciesClient
	totalDuration := time.Since(startTime)
	logrus.Infof("%s | Successfully created client in %v (client creation: %v)", funcName, totalDuration, clientCreateDuration)

	return
}

func (s *Session) GetManagedRuleSetsClient(subID string) (err error) {
	funcName := helpers.GetFunctionName()

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

	if s.ClientCredential == nil {
		err = s.GetClientCredential()
		if err != nil {
			return
		}
	}

	logrus.Debugf("creating new manage rule sets client for sub: %s", subID)

	frontDoorManagedRuleSetsClient, merr := armfrontdoor.NewManagedRuleSetsClient(subID, s.ClientCredential, nil)
	if merr != nil {
		return fmt.Errorf(merr.Error(), helpers.GetFunctionName())
	}

	s.FrontDoorsManagedRuleSetsClients[subID] = frontDoorManagedRuleSetsClient

	return
}
