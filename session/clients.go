package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"

	"github.com/jonhadfield/azwaf/logging"
)

// azwafClientOptions is the retry and telemetry configuration every Azure
// client is built with. Two of the four getters passed nil and so ran on SDK
// defaults, which looked accidental rather than intended.
func azwafClientOptions() *arm.ClientOptions {
	return &arm.ClientOptions{
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
}

// getOrCreateClient returns early when a client for subID is already cached and
// otherwise builds one, storing it for next time.
//
// The four getters each had a copy of this, and had drifted: two checked for a
// nil session, two checked for an empty subscription id, and two passed client
// options. None checked all three.
func getOrCreateClient[T any](s *Session, subID, kind string, clients *map[string]*T,
	newClient func(string, azcore.TokenCredential, *arm.ClientOptions) (*T, error),
) error {
	if subID == "" {
		return fmt.Errorf("%s client - subscription id is mandatory", kind)
	}

	if *clients == nil {
		*clients = make(map[string]*T)
	}

	if (*clients)[subID] != nil {
		logging.Debugf("re-using %s client for subscription: %s", kind, subID)

		return nil
	}

	if s.ClientCredential == nil {
		if err := s.GetClientCredential(); err != nil {
			return err
		}
	}

	logging.Debugf("creating %s client for subscription: %s", kind, subID)

	c, err := newClient(subID, s.ClientCredential, azwafClientOptions())
	if err != nil {
		return fmt.Errorf("%s client - %w", kind, err)
	}

	(*clients)[subID] = c

	return nil
}

// GetFrontDoorPoliciesClient caches a Front Door WAF policies client per subscription.
func (s *Session) GetFrontDoorPoliciesClient(subID string) error {
	// checked here rather than in the helper: taking the address of a field on
	// a nil session panics before the call is made
	if s == nil {
		return errors.New("session is nil")
	}

	return getOrCreateClient(s, subID, "front door policies", &s.FrontDoorPoliciesClients,
		armfrontdoor.NewPoliciesClient)
}

// GetAppGWPoliciesClient caches an Application Gateway WAF policies client per subscription.
func (s *Session) GetAppGWPoliciesClient(subID string) error {
	if s == nil {
		return errors.New("session is nil")
	}

	return getOrCreateClient(s, subID, "application gateway waf policies", &s.AppGWPoliciesClients,
		armnetwork.NewWebApplicationFirewallPoliciesClient)
}

// GetManagedRuleSetsClient caches a Front Door managed rule sets client per subscription.
func (s *Session) GetManagedRuleSetsClient(subID string) error {
	if s == nil {
		return errors.New("session is nil")
	}

	return getOrCreateClient(s, subID, "front door managed rule sets", &s.FrontDoorsManagedRuleSetsClients,
		armfrontdoor.NewManagedRuleSetsClient)
}
