package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"

	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"
)

func (s *Session) GetFrontDoorPoliciesClient(subID string) (err error) {
	funcName := helpers.GetFunctionName()
	startTime := time.Now()

	logging.Debugf("%s | Starting GetFrontDoorPoliciesClient for subscription: %s", funcName, subID)

	if s == nil {
		return errors.New("session is nil")
	}

	if s.FrontDoorPoliciesClients == nil {
		s.FrontDoorPoliciesClients = make(map[string]*armfrontdoor.PoliciesClient)
	}

	if s.FrontDoorPoliciesClients[subID] != nil {
		logging.Debugf("%s | Re-using existing client (took: %v)", funcName, time.Since(startTime))
		return nil
	}

	logging.Debugf("%s | Creating new policies client for subscription: %s", funcName, subID)

	if s.ClientCredential == nil {
		credStartTime := time.Now()
		logging.Debugf("%s | Getting client credentials...", funcName)
		err = s.GetClientCredential()
		credDuration := time.Since(credStartTime)
		logging.Debugf("%s | Client credential retrieval took: %v", funcName, credDuration)
		if err != nil {
			logging.Errorf("%s | Failed to get client credentials: %v", funcName, err)
			return
		}
	}

	clientCreateStartTime := time.Now()
	logging.Debugf("%s | Creating Azure Frontdoor client with optimized settings...", funcName)

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
		logging.Errorf("%s | Failed to create client after %v: %s", funcName, clientCreateDuration, merr.Error())
		return fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	s.FrontDoorPoliciesClients[subID] = frontDoorPoliciesClient
	totalDuration := time.Since(startTime)
	logging.Debugf("%s | Successfully created client in %v (client creation: %v)", funcName, totalDuration, clientCreateDuration)

	return
}

// GetAppGWPoliciesClient creates (or returns a cached) Application Gateway WAF
// policies client for the given subscription.
func (s *Session) GetAppGWPoliciesClient(subID string) error {
	funcName := helpers.GetFunctionName()

	if s == nil {
		return errors.New("session is nil")
	}

	if subID == "" {
		return fmt.Errorf("%s - subscription id is mandatory", funcName)
	}

	if s.AppGWPoliciesClients == nil {
		s.AppGWPoliciesClients = make(map[string]*armnetwork.WebApplicationFirewallPoliciesClient)
	}

	if s.AppGWPoliciesClients[subID] != nil {
		logging.Debugf("re-using application gateway waf policies client for subscription: %s", subID)

		return nil
	}

	if s.ClientCredential == nil {
		if err := s.GetClientCredential(); err != nil {
			return err
		}
	}

	logging.Debugf("creating application gateway waf policies client for subscription: %s", subID)

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

	c, merr := armnetwork.NewWebApplicationFirewallPoliciesClient(subID, s.ClientCredential, clientOptions)
	if merr != nil {
		return fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	s.AppGWPoliciesClients[subID] = c

	return nil
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
		logging.Debugf("re-using arm front door rules sets client for subscription: %s", subID)

		return nil
	}

	logging.Debugf("creating arm front door managed rule sets client for subscription: %s", subID)

	if s.ClientCredential == nil {
		err = s.GetClientCredential()
		if err != nil {
			return
		}
	}

	logging.Debugf("creating new manage rule sets client for sub: %s", subID)

	frontDoorManagedRuleSetsClient, merr := armfrontdoor.NewManagedRuleSetsClient(subID, s.ClientCredential, nil)
	if merr != nil {
		return fmt.Errorf("%s - %w", helpers.GetFunctionName(), merr)
	}

	s.FrontDoorsManagedRuleSetsClients[subID] = frontDoorManagedRuleSetsClient

	return
}
