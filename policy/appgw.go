package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/wI2L/jsondiff"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"
	"github.com/jonhadfield/azwaf/session"
)

// WAF policy resource type constants. These are the value of the 8th component
// (index 7) of an Azure resource ID and are used to discriminate between
// Front Door and Application Gateway WAF policies.
const (
	ResourceTypeFrontDoorWAF = "frontdoorWebApplicationFirewallPolicies"
	ResourceTypeAppGWWAF     = "ApplicationGatewayWebApplicationFirewallPolicies"

	// WAFType values written into backup files so restore can dispatch to
	// the correct API. Empty / missing == FrontDoor for backward compatibility
	// with backups produced by older versions.
	WAFTypeFrontDoor = "FrontDoor"
	WAFTypeAppGW     = "ApplicationGateway"

	appGWPolicyGetTimeout = 120 * time.Second
)

// WAFTypeFromResourceID returns WAFTypeAppGW or WAFTypeFrontDoor based on the
// resource type embedded in the resource id. Comparison is case-insensitive
// because Azure occasionally returns resource ids with inconsistent casing.
func WAFTypeFromResourceID(rawID string) string {
	rid := config.ParseResourceID(rawID)

	if strings.EqualFold(rid.ResourceType, ResourceTypeAppGWWAF) {
		return WAFTypeAppGW
	}

	return WAFTypeFrontDoor
}

// WrappedAppGWPolicy is the AppGW analogue of WrappedPolicy and uses the same
// JSON shape so existing storage/file plumbing can be reused.
type WrappedAppGWPolicy struct {
	Date           time.Time
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Policy         armnetwork.WebApplicationFirewallPolicy
	PolicyID       string
	AppVersion     string
	WAFType        string
}

// GetRawAppGWPolicy retrieves a single Application Gateway WAF policy.
func GetRawAppGWPolicy(s *session.Session, subscription, resourceGroup, name string) (*armnetwork.WebApplicationFirewallPolicy, error) {
	funcName := helpers.GetFunctionName()

	if err := s.GetAppGWPoliciesClient(subscription); err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	logging.Debugf("%s | getting AppGW WAF policy %s in subscription %s resource group %s",
		funcName, name, subscription, resourceGroup)

	ctx, cancel := context.WithTimeout(context.Background(), appGWPolicyGetTimeout)
	defer cancel()

	resp, merr := s.AppGWPoliciesClients[subscription].Get(ctx, resourceGroup, name, nil)
	if merr != nil {
		// wrap, don't flatten: isAppGWNotFound needs the *azcore.ResponseError
		// to remain in the chain
		return nil, fmt.Errorf("%s - %w", funcName, merr)
	}

	return &resp.WebApplicationFirewallPolicy, nil
}

// GetAllAppGWPolicies lists every Application Gateway WAF policy in the
// subscription, optionally filtered by FilterResourceIDs.
func GetAllAppGWPolicies(s *session.Session, i GetWrappedPoliciesInput) ([]armnetwork.WebApplicationFirewallPolicy, error) {
	funcName := helpers.GetFunctionName()

	if err := s.GetAppGWPoliciesClient(i.SubscriptionID); err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	ctx := context.Background()

	top := i.Max
	if top == 0 {
		top = MaxPoliciesToFetch
	}

	logging.Debugf("listing first %d AppGW WAF policies in subscription: %s", top, i.SubscriptionID)

	pager := s.AppGWPoliciesClients[i.SubscriptionID].NewListAllPager(nil)

	var gres []armnetwork.WebApplicationFirewallPolicy

	var total int

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s failed to advance page of AppGW WAF policies - %w", funcName, err)
		}

		for _, resource := range page.Value {
			if resource.ID == nil {
				return nil, fmt.Errorf("%s | Azure returned an AppGW WAF Policy without a resource ID: %+v", funcName, resource)
			}

			if len(i.FilterResourceIDs) == 0 || slices.Contains(i.FilterResourceIDs, *resource.ID) {
				gres = append(gres, *resource)
			}

			total++

			if total == top {
				return gres, nil
			}
		}
	}

	logging.Debugf("retrieved %d AppGW WAF resources", total)

	return gres, nil
}

// GetWrappedAppGWPoliciesFromRawIDs mirrors GetWrappedPoliciesFromRawIDs but
// for AppGW. Filter resource ids must already be parsed AppGW WAF policy ids.
func GetWrappedAppGWPoliciesFromRawIDs(s *session.Session, i GetWrappedPoliciesInput) ([]WrappedAppGWPolicy, error) {
	funcName := helpers.GetFunctionName()

	var rids []config.ResourceID

	if len(i.FilterResourceIDs) > 0 {
		for _, rawID := range i.FilterResourceIDs {
			rid := config.ParseResourceID(rawID)
			if rid.Name == "" {
				return nil, fmt.Errorf("%s - invalid AppGW WAF policy id: %s", funcName, rawID)
			}

			rids = append(rids, rid)
		}
	} else {
		all, err := GetAllAppGWPolicies(s, i)
		if err != nil {
			return nil, fmt.Errorf("%s - %w", funcName, err)
		}

		for _, p := range all {
			rids = append(rids, config.ParseResourceID(*p.ID))
		}
	}

	var out []WrappedAppGWPolicy

	for _, rid := range rids {
		logging.Debugf("retrieving raw AppGW WAF policy: %s %s %s", rid.SubscriptionID, rid.ResourceGroup, rid.Name)

		p, err := GetRawAppGWPolicy(s, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
		if err != nil {
			return nil, fmt.Errorf("%s - %w", funcName, err)
		}

		out = append(out, WrappedAppGWPolicy{
			Date:           time.Now().UTC(),
			SubscriptionID: rid.SubscriptionID,
			ResourceGroup:  rid.ResourceGroup,
			Name:           rid.Name,
			Policy:         *p,
			PolicyID:       rid.Raw,
			AppVersion:     i.AppVersion,
			WAFType:        WAFTypeAppGW,
		})
	}

	return out, nil
}

// PushAppGWPolicyInput defines the input for PushAppGWPolicy.
type PushAppGWPolicyInput struct {
	Name          string
	Subscription  string
	ResourceGroup string
	Policy        armnetwork.WebApplicationFirewallPolicy
	Debug         bool
}

// PushAppGWPolicy creates or updates an Application Gateway WAF policy.
// The AppGW SDK exposes CreateOrUpdate as a synchronous call.
func PushAppGWPolicy(s *session.Session, i *PushAppGWPolicyInput) error {
	funcName := helpers.GetFunctionName()

	logging.Debugf("pushing AppGW WAF policy %s...", i.Name)

	if err := s.GetAppGWPoliciesClient(i.Subscription); err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	ctx := context.Background()

	_, err := s.AppGWPoliciesClients[i.Subscription].CreateOrUpdate(ctx, i.ResourceGroup, i.Name, i.Policy, nil)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	logging.Infof("AppGW WAF policy %s updated", i.Name)

	return nil
}

// LoadWrappedAppGWPolicyFromFile loads a WrappedAppGWPolicy backup file.
func LoadWrappedAppGWPolicyFromFile(data []byte) (WrappedAppGWPolicy, error) {
	funcName := helpers.GetFunctionName()

	var wp WrappedAppGWPolicy
	if err := json.Unmarshal(data, &wp); err != nil {
		return WrappedAppGWPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	if wp.Policy.Properties == nil {
		return WrappedAppGWPolicy{}, fmt.Errorf("%s - wrapped AppGW policy is invalid", funcName)
	}

	return wp, nil
}

// GenerateAppGWPolicyPatch reuses the JSON-path-based diff stats from the FD
// patch generator so restore confirmation prompts work consistently.
func GenerateAppGWPolicyPatch(original interface{}, newPolicy armnetwork.WebApplicationFirewallPolicy) (GeneratePolicyPatchOutput, error) {
	funcName := helpers.GetFunctionName()

	var output GeneratePolicyPatchOutput

	originalBytes, err := marshalOriginal(original)
	if err != nil {
		return output, fmt.Errorf("%s - %w", funcName, err)
	}

	newJSON, err := json.MarshalIndent(newPolicy, "", "    ")
	if err != nil {
		return output, fmt.Errorf("%s - %w", funcName, err)
	}

	patch, err := jsondiff.CompareJSON(originalBytes, newJSON)
	if err != nil {
		return output, fmt.Errorf("%s - %w", funcName, err)
	}

	return calculatePatchStats(patch), nil
}
