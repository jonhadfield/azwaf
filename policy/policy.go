package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"

	"github.com/jonhadfield/azwaf/cache"

	// H "github.com/jonhadfield/azwaf/helpers"

	"github.com/wI2L/jsondiff"

	"github.com/jonhadfield/azwaf/session"
)

const (
	// Order is:
	// - 1: Log (manual 0-999, azwaf 1000-1999)
	// - 2: Allow (manual 2000-2999, azwaf 3000-3999)
	// - 3: Block (manual 4000-4999, azwaf 5000-5999)

	// MaxPoliciesToFetch is the maximum number to attempt to retrieve (not an Azure limit)
	MaxPoliciesToFetch = 200
	// MaxFrontDoorsToFetch is the maximum number to attempt to retrieve (not an Azure limit)
	MaxFrontDoorsToFetch = 100
	// MaxCustomRules is the hard limit on the number of allowed Custom rules
	MaxCustomRules = 90
	// MaxIPMatchValues is Azure's hard limit on IPMatch values per rule
	MaxIPMatchValues = 600

	// AllowNetsPrefix is the prefix for Custom Rules used for allowing IP networks
	AllowNetsPrefix = "AllowNets"

	// MaxMatchValuesPerColumn is the number of match values to output per column when showing policies and rules
	MaxMatchValuesPerColumn = 3
	// MaxMatchValuesOutput is the maximum number of match values to output when showing policies and rules
	MaxMatchValuesOutput = 9

	// policyGetTimeout specifies how long to wait when fetching a policy
	policyGetTimeout = 120 * time.Second
)

const (
	maxExclusionLimit                 = 100
	maxExclusionLimitWarningThreshold = 95
	// Errors
	errScopeUndefined         = "scope undefined"
	errScopeInvalid           = "scope invalid"
	errExclusionAlreadyExists = "already exists"
	errRuleNotFound           = "rule not found"
	errRuleGroupNotFound      = "rule group not found"
	errPolicyNotDefined       = "policy not defined"
	WAFResourceIDHashMapName  = "WAFResourceIDHashMap"
)

var ErrInvalidRuleType = errors.New("invalid rule type")

func GetWAFResourceIDHashMap(s *session.Session) (hashMap WAFResourceIDHashMap, err error) {
	funcName := helpers.GetFunctionName()

	logging.Debugf("%s | attempting to read waf resource id hash map from cache", funcName)

	cacheEntry, err := cache.Read(s, WAFResourceIDHashMapName)
	if err != nil {
		return hashMap, fmt.Errorf("%s - %w", funcName, err)
	}

	if cacheEntry == "" {
		return
	}

	if jerr := json.Unmarshal([]byte(cacheEntry), &hashMap); jerr != nil {
		err = fmt.Errorf("%s - %w", funcName, jerr)
	}

	return
}

func SaveWAFResourceIDHashMap(s *session.Session, res []armfrontdoor.WebApplicationFirewallPolicy) error {
	funcName := helpers.GetFunctionName()

	logging.Debugf("attempting to save waf resource id hash map from cache")

	var hashMap WAFResourceIDHashMap

	for _, r := range res {
		hash := computeAdler32(*r.ID)

		hashMap.Entries = append(hashMap.Entries, WAFResourceIDHashMapEntry{
			Hash:       hash,
			ResourceID: *r.ID,
		})
	}

	mHashMap, err := json.Marshal(hashMap)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	err = cache.Write(s, WAFResourceIDHashMapName, string(mHashMap))
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	return nil
}

func GetWAFResourceIDFromCacheByHash(s *session.Session, hash string) (string, error) {
	funcName := helpers.GetFunctionName()

	if s == nil {
		var serr error

		s, serr = session.New()
		if serr != nil {
			return "", fmt.Errorf("%s - %w", funcName, serr)
		}
	}

	hashMap, err := GetWAFResourceIDHashMap(s)
	if err != nil {
		return "", fmt.Errorf("%s - %w", funcName, err)
	}

	if len(hashMap.Entries) == 0 {
		logging.Debugf("no hashmap entries were loaded")

		return "", nil
	}

	for _, entry := range hashMap.Entries {
		if entry.Hash == hash {
			logging.Debugf("%s | found resource id matching hash %s in cache", funcName, hash)

			return entry.ResourceID, nil
		}
	}

	return "", nil
}

type WAFResourceIDHashMapEntry struct {
	Hash       string
	ResourceID string
}

type WAFResourceIDHashMap struct {
	Entries []WAFResourceIDHashMapEntry
}

// GetPolicyResourceIDByHash resolves a policy hash to its parsed resource id.
// It is GetPolicyRIDByHash with the result parsed: the lookup, the cache read
// and the hash-map save all live there, and were duplicated here.
func GetPolicyResourceIDByHash(s *session.Session, subID, hash string) (config.ResourceID, error) {
	rawID, err := GetPolicyRIDByHash(s, subID, hash)
	if err != nil {
		return config.ResourceID{}, err
	}

	return config.ParseResourceID(rawID), nil
}

func GetPolicyRIDByHash(s *session.Session, subID, hash string) (string, error) {
	// check cache if we have a match
	pID, err := GetWAFResourceIDFromCacheByHash(s, hash)
	if err != nil {
		logging.Warn(err)
	}

	if pID != "" {
		return pID, nil
	}

	o, perr := GetAllPolicies(s, GetWrappedPoliciesInput{
		SubscriptionID: subID,
	})
	if perr != nil {
		return "", perr
	}

	if err = SaveWAFResourceIDHashMap(s, o); err != nil {
		return "", fmt.Errorf("failed to save waf resource id hash map: %w", err)
	}

	for _, p := range o {
		if computeAdler32(*p.ID) == hash {
			pID = *p.ID

			return pID, nil
		}
	}

	return pID, fmt.Errorf("resource with hash %s could not be found", hash)
}

type GetWAFPolicyResourceIDInput struct {
	SubscriptionID string
	RawPolicyID    string
	ConfigPath     string
}

func GetWAFPolicyResourceID(s *session.Session, in GetWAFPolicyResourceIDInput) (config.ResourceID, error) {
	// try parsing as azure resource id
	resourceID := config.ParseResourceID(in.RawPolicyID)
	if resourceID.Name != "" {
		return resourceID, nil
	}

	// try loading config file to check for policy aliases
	fileConfig, err := config.LoadFileConfig(in.ConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return config.ResourceID{}, fmt.Errorf("failed to load config file: %w", err)
	}

	// get resource id from loaded alias
	if fileConfig.PolicyAliases != nil {
		if fileConfig.PolicyAliases[in.RawPolicyID] != "" {
			resourceID = config.ParseResourceID(fileConfig.PolicyAliases[in.RawPolicyID])
			if resourceID.Name != "" {
				return resourceID, nil
			}
		}
	}

	// if it's not a hash, we have nothing left to process
	if !IsRIDHash(in.RawPolicyID) {
		return config.ResourceID{}, fmt.Errorf("failed to find provided policy: %s", in.RawPolicyID)
	}

	// processing policy hash
	if in.SubscriptionID == "" {
		return resourceID, fmt.Errorf("using a policy hash requires a subscription id")
	}

	if err = validateSubscriptionID(in.SubscriptionID); err != nil {
		return config.ResourceID{}, err
	}

	rawPolicyID, err := GetPolicyRIDByHash(s, in.SubscriptionID, in.RawPolicyID)
	if err != nil {
		return config.ResourceID{}, err
	}

	return config.ParseResourceID(rawPolicyID), err
}

func GetRawPolicy(s *session.Session, subscription, resourceGroup, name string) (*armfrontdoor.WebApplicationFirewallPolicy, error) {
	funcName := helpers.GetFunctionName()
	startTime := time.Now()

	logging.Debugf("%s | Starting GetRawPolicy for %s/%s/%s", funcName, subscription, resourceGroup, name)

	// Time client initialization
	clientStartTime := time.Now()
	err := s.GetFrontDoorPoliciesClient(subscription)
	clientDuration := time.Since(clientStartTime)
	logging.Debugf("%s | Client initialization took: %v", funcName, clientDuration)

	if err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	logging.Debugf("%s | getting AFD Policy %s from subscription %s and resource group %s",
		funcName,
		name,
		subscription,
		resourceGroup)

	logging.Debugf("getting policy %s from subscription: %s resource group: %s",
		name,
		subscription,
		resourceGroup)

	ctx, cancel := context.WithTimeout(context.Background(), policyGetTimeout)
	defer cancel()

	options := armfrontdoor.PoliciesClientGetOptions{}

	// Time the actual API call
	apiStartTime := time.Now()
	logging.Debugf("%s | Making API call to Azure (timeout: %v)", funcName, policyGetTimeout)

	pcg, merr := s.FrontDoorPoliciesClients[subscription].Get(ctx, resourceGroup, name, &options)

	apiDuration := time.Since(apiStartTime)
	totalDuration := time.Since(startTime)

	logging.Debugf("%s | API call completed in: %v (total time: %v)", funcName, apiDuration, totalDuration)

	if merr != nil {
		logging.Errorf("%s | API call failed after %v: %s", funcName, apiDuration, merr.Error())

		// wrap, don't flatten: callers can then detect typed
		// *azcore.ResponseError values (e.g. 404s) in the chain
		return nil, fmt.Errorf("%s - %w", funcName, merr)
	}

	logging.Debugf("%s | Successfully retrieved policy in %v", funcName, totalDuration)
	return &pcg.WebApplicationFirewallPolicy, nil
}

type BaseCLIInput struct {
	AppVersion     string
	AutoBackup     bool
	Debug          bool
	ConfigPath     string
	SubscriptionID string
	Quiet          bool
	DryRun         bool
}

type DeleteCustomRulesCLIInput struct {
	// BaseCLIInput is embedded, not a named field: it previously sat alongside
	// duplicate SubscriptionID/DryRun/ConfigPath/Debug fields that the CLI
	// never populated, so reads of the outer twins silently saw zero values
	// and --dry-run pushed anyway.
	BaseCLIInput
	// Session optionally provides a pre-configured session; when nil a new
	// one is created. Tests inject a fake-backed session here.
	Session   *session.Session
	PolicyID  string
	RID       config.ResourceID
	Name      string
	NameMatch *regexp.Regexp
	Priority  string
	MaxRules  int
}

type DeleteCustomRulesPrefixesInput struct {
	Policy      *armfrontdoor.WebApplicationFirewallPolicy
	RID         config.ResourceID
	Name        string
	NameMatch   *regexp.Regexp
	Priority    int
	PrioritySet bool
	MaxRules    int
	Debug       bool
}

type DeleteManagedRuleExclusionInput struct {
	DryRun                bool
	RID                   config.ResourceID
	RuleSetType           *string
	RuleSetVersion        *string
	RuleGroup             string
	RuleID                string
	ShowDiff              bool
	ExclusionRuleVariable armfrontdoor.ManagedRuleExclusionMatchVariable
	ExclusionRuleOperator armfrontdoor.ManagedRuleExclusionSelectorMatchOperator
	ExclusionRuleSelector string
	Debug                 bool
	// helper attribute: used to assess scope of change
	Scope ExclusionScope
}

func GetAllPolicies(s *session.Session, i GetWrappedPoliciesInput) ([]armfrontdoor.WebApplicationFirewallPolicy, error) {
	funcName := helpers.GetFunctionName()

	err := s.GetFrontDoorPoliciesClient(i.SubscriptionID)
	if err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	ctx := context.Background()

	top := int32(i.Max)
	if i.Max == 0 {
		top = MaxPoliciesToFetch
	}

	logging.Debugf("listing first %d Policies in Subscription: %s", top, i.SubscriptionID)

	pager := s.FrontDoorPoliciesClients[i.SubscriptionID].NewListBySubscriptionPager(nil)

	var gres []armfrontdoor.WebApplicationFirewallPolicy

	var total int

	for pager.More() {
		var page armfrontdoor.PoliciesClientListBySubscriptionResponse

		page, err = pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s failed to advance page of waf policies - %w", funcName, err)
		}

		for _, resource := range page.Value {
			if resource.ID == nil {
				return nil, fmt.Errorf("%s | Azure returned a WAF Policy without a resource ID: %+v", funcName, resource)
			}

			if len(i.FilterResourceIDs) == 0 || slices.Contains(i.FilterResourceIDs, *resource.ID) {
				gres = append(gres, *resource)
			}

			total++

			// passing top as top number of items isn't working due to an API bug
			// if we have reached top here, then return
			if total == int(top) {
				return gres, nil
			}
		}
	}

	logging.Debugf("retrieved %d resources", total)

	return gres, err
}

func GetWrappedPoliciesFromRawIDs(s *session.Session, i GetWrappedPoliciesInput) (GetWrappedPoliciesOutput, error) {
	funcName := helpers.GetFunctionName()

	var rids []config.ResourceID

	var err error

	if len(i.FilterResourceIDs) > 0 {
		for _, rawID := range i.FilterResourceIDs {
			var rid config.ResourceID

			rid, err = GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
				SubscriptionID: i.SubscriptionID,
				RawPolicyID:    rawID,
				ConfigPath:     i.Config,
			})
			if err != nil {
				return GetWrappedPoliciesOutput{}, err
			}

			rids = append(rids, rid)
		}
	} else {
		// retrieve all Policies as generic resources
		var gres []armfrontdoor.WebApplicationFirewallPolicy

		gres, err = GetAllPolicies(s, i)
		if err != nil {
			return GetWrappedPoliciesOutput{}, fmt.Errorf("%s - %w", funcName, err)
		}

		for _, g := range gres {
			rids = append(rids, config.ParseResourceID(*g.ID))
		}
	}

	var o GetWrappedPoliciesOutput

	for _, rid := range rids {
		var p *armfrontdoor.WebApplicationFirewallPolicy

		logging.Debugf("retrieving raw Policy with: %s %s %s", rid.SubscriptionID, rid.ResourceGroup, rid.Name)

		p, err = GetRawPolicy(s, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
		if err != nil {
			return GetWrappedPoliciesOutput{}, fmt.Errorf("%s - %w", funcName, err)
		}

		wp := WrappedPolicy{
			Date:           time.Now().UTC(),
			SubscriptionID: rid.SubscriptionID,
			ResourceGroup:  rid.ResourceGroup,
			Name:           rid.Name,
			Policy:         *p,
			PolicyID:       rid.Raw,
			AppVersion:     i.AppVersion,
		}

		o.Policies = append(o.Policies, wp)
	}

	return o, nil
}

// MatchExistingPolicyByID returns the raw Policy matched by the Policy id of its origin, e.g. where the backup was from
func MatchExistingPolicyByID(targetPolicyID string, existingPolicies []WrappedPolicy) (bool, WrappedPolicy) {
	for x := range existingPolicies {
		if strings.EqualFold(existingPolicies[x].PolicyID, targetPolicyID) {
			return true, existingPolicies[x]
		}
	}

	return false, WrappedPolicy{}
}

type WrappedPolicy struct {
	Date           time.Time
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Policy         armfrontdoor.WebApplicationFirewallPolicy
	PolicyID       string
	AppVersion     string
	WAFType        string `json:",omitempty"`
}

type GeneratePolicyPatchInput struct {
	Original interface{}
	New      armfrontdoor.WebApplicationFirewallPolicy
}

type GeneratePolicyPatchOutput struct {
	TotalDifferences        int
	TotalRuleDifferences    int
	CustomRuleAdditions     int
	CustomRuleChanges       int
	CustomRuleRemovals      int
	CustomRuleReplacements  int
	ManagedRuleChanges      int
	ManagedRuleAdditions    int
	ManagedRuleRemovals     int
	ManagedRuleReplacements int
}

// marshalOriginal renders a policy as indented json for diffing. It accepts
// either WAF type, in raw or wrapped form, and passes an already-encoded byte
// slice straight back.
//
// The Front Door and Application Gateway paths had a copy of this each, over
// their own type sets. They are unexported with one call site apiece, both
// passing a concrete type, so the split bought no safety the compiler was not
// already providing.
func marshalOriginal(original interface{}) ([]byte, error) {
	switch v := original.(type) {
	case []byte:
		return v, nil
	case armfrontdoor.WebApplicationFirewallPolicy:
		return json.MarshalIndent(v, "", "    ")
	case WrappedPolicy:
		return json.MarshalIndent(v.Policy, "", "    ")
	case armnetwork.WebApplicationFirewallPolicy:
		return json.MarshalIndent(v, "", "    ")
	case WrappedAppGWPolicy:
		return json.MarshalIndent(v.Policy, "", "    ")
	default:
		return nil, fmt.Errorf("unexpected policy type: %s", reflect.TypeOf(original).String())
	}
}

// patchPathInSection reports whether a JSON patch path is the section itself
// or anything beneath it. The exact match matters: adding or removing an
// entire section (e.g. a policy gaining customRules where it had none)
// produces a single op at the section path with no trailing slash.
func patchPathInSection(path, section string) bool {
	return path == section || strings.HasPrefix(path, section+"/")
}

func calculatePatchStats(patch jsondiff.Patch) GeneratePolicyPatchOutput {
	var output GeneratePolicyPatchOutput

	output.TotalDifferences = len(patch)

	const (
		customRulesPath  = "/properties/customRules"
		managedRulesPath = "/properties/managedRules"
	)

	for _, op := range patch {
		logging.Trace(op.String())

		switch op.Type {
		case "add":
			if patchPathInSection(string(op.Path), customRulesPath) {
				output.CustomRuleAdditions++
			}

			if patchPathInSection(string(op.Path), managedRulesPath) {
				output.ManagedRuleAdditions++
			}
		case "remove":
			if patchPathInSection(string(op.Path), customRulesPath) {
				output.CustomRuleRemovals++
			}

			if patchPathInSection(string(op.Path), managedRulesPath) {
				output.ManagedRuleRemovals++
			}
		case "replace":
			if patchPathInSection(string(op.Path), customRulesPath) {
				output.CustomRuleReplacements++
			}

			if patchPathInSection(string(op.Path), managedRulesPath) {
				output.ManagedRuleReplacements++
			}
		}
	}

	output.CustomRuleChanges = output.CustomRuleAdditions + output.CustomRuleRemovals + output.CustomRuleReplacements
	output.ManagedRuleChanges = output.ManagedRuleAdditions + output.ManagedRuleRemovals + output.ManagedRuleReplacements
	output.TotalRuleDifferences = output.CustomRuleChanges + output.ManagedRuleChanges

	return output
}

func GeneratePolicyPatch(i *GeneratePolicyPatchInput) (GeneratePolicyPatchOutput, error) {
	funcName := helpers.GetFunctionName()

	var output GeneratePolicyPatchOutput

	originalBytes, err := marshalOriginal(i.Original)
	if err != nil {
		return output, fmt.Errorf("%s - %w", funcName, err)
	}

	newPolicyJSON, err := json.MarshalIndent(i.New, "", "    ")
	if err != nil {
		return output, fmt.Errorf("%s - %w", funcName, err)
	}

	patch, err := jsondiff.CompareJSON(originalBytes, newPolicyJSON)
	if err != nil {
		return output, fmt.Errorf("%s - %w", funcName, err)
	}

	output = calculatePatchStats(patch)

	return output, nil
}

// validatePolicyLimits checks a policy against the Azure limits azwaf can
// determine locally. Without it an over-limit policy is only rejected once it
// reaches the API, and the caller has already paid for a fetch, a diff and an
// auto-backup by then.
func validatePolicyLimits(p *armfrontdoor.WebApplicationFirewallPolicy) error {
	if count := len(policyCustomRules(p)); count > MaxCustomRules {
		return fmt.Errorf("policy has %d custom rules, exceeding Azure's limit of %d",
			count, MaxCustomRules)
	}

	// each scope is capped independently, so report the specific one that is
	// over rather than a total that maps to no single limit
	for _, scope := range policyExclusionScopes(p) {
		if scope.count > maxExclusionLimit {
			return fmt.Errorf("%s %s has %d exclusions, exceeding Azure's limit of %d per scope",
				scope.scope.Lower(), scope.name, scope.count, maxExclusionLimit)
		}
	}

	return nil
}

func ProcessPolicyChanges(input *ProcessPolicyChangesInput) error {
	funcName := helpers.GetFunctionName()

	// reject before spending a fetch, a diff and a backup on a policy the API
	// will refuse. This runs ahead of the dry-run return so a dry run reports
	// the problem too
	if err := validatePolicyLimits(&input.PolicyPostChange); err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	// get existing policy before change to allow for diff and backups
	preChange, err := GetRawPolicy(input.Session, input.SubscriptionID, input.ResourceGroup, input.PolicyName)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	if input.ShowDiff {
		if err = DisplayPolicyDiff(preChange, input.PolicyPostChange); err != nil {
			return fmt.Errorf("%s - %w", funcName, err)
		}
	}

	if input.DryRun {
		logging.Infof("%s | changes were not applied as dry-run was requested", funcName)

		return nil
	}

	if input.Backup {
		err = BackupPolicy(&WrappedPolicy{
			SubscriptionID: input.SubscriptionID,
			ResourceGroup:  input.ResourceGroup,
			Name:           input.PolicyName,
			Policy:         *preChange,
			PolicyID:       *preChange.ID,
			AppVersion:     input.Session.AppVersion,
		}, nil, "", true, false, input.Session.BackupsDir)
		if err != nil {
			return err
		}
	}

	return PushPolicy(input.Session, &PushPolicyInput{
		Name:          input.PolicyName,
		Subscription:  input.SubscriptionID,
		ResourceGroup: input.ResourceGroup,
		Policy:        input.PolicyPostChange,
		Debug:         input.Debug,
		Async:         input.Async,
	})
}
