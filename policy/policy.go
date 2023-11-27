package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jonhadfield/azwaf/config"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/cache"

	// H "github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	"github.com/wI2L/jsondiff"
	"golang.org/x/exp/slices"
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
	// MaxLogNetsRules is the maximum number of Custom rules to create from Azure's hard limit of 90 per Policy
	MaxLogNetsRules = 10
	// MaxBlockNetsRules is the maximum number of Custom rules to create from Azure's hard limit of 90 per Policy
	MaxBlockNetsRules = 40
	// MaxAllowNetsRules is the maximum number of Custom rules to create from Azure's hard limit of 90 per Policy
	MaxAllowNetsRules = 10
	// MaxIPMatchValues is Azure's hard limit on IPMatch values per rule
	MaxIPMatchValues = 600

	// LogNetsPrefix is the prefix for Custom Rules used for logging IP networks
	LogNetsPrefix = "LogNets"
	// LogNetsPriorityStart is the first Custom rule priority number
	// Manual log rules should be numbered below 1000
	LogNetsPriorityStart = 1000

	// AllowNetsPrefix is the prefix for Custom Rules used for allowing IP networks
	AllowNetsPrefix = "AllowNets"
	// AllowNetsPriorityStart is the first Custom rule priority number
	// Manual allow rules should be numbered 2000-2999
	AllowNetsPriorityStart = 3000

	BlockNetsPriorityStart = 5000

	// MaxMatchValuesPerColumn is the number of match values to output per column when showing policies and rules
	MaxMatchValuesPerColumn = 3
	// MaxMatchValuesOutput is the maximum number of match values to output when showing policies and rules
	MaxMatchValuesOutput = 9
)

const (
	// Azure limits - https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-front-door-classic-limits
	MaxConditionsPerCustomRule        = 10
	maxExclusionLimit                 = 100
	maxExclusionLimitWarningThreshold = 95
	ScopeRuleSet                      = "ruleSet"
	ScopeRuleGroup                    = "ruleGroup"
	ScopeRule                         = "rule"
	// Errors
	errScopeUndefined         = "scope undefined"
	errScopeInvalid           = "scope invalid"
	errExclusionAlreadyExists = "already exists"
	errRuleNotFound           = "rule not found"
	errRuleGroupNotFound      = "rule group not found"
	errInvalidMatchVariable   = "invalid match variable"
	errPolicyNotDefined       = "policy not defined"
	WAFResourceIDHashMapName  = "WAFResourceIDHashMap"
	defaultRuleSetPrefix      = "Microsoft_DefaultRuleSet"
	botManagerRuleSetPrefix   = "Microsoft_BotManagerRuleSet"
)

func GetWAFResourceIDHashMap(s *session.Session) (hashMap WAFResourceIDHashMap, err error) {
	funcName := GetFunctionName()

	logrus.Debugf("%s | attempting to read waf resource id hash map from cache", funcName)

	cacheEntry, err := cache.Read(s, WAFResourceIDHashMapName)
	if err != nil {
		return hashMap, fmt.Errorf(err.Error(), funcName)
	}

	if cacheEntry == "" {
		return
	}

	jerr := json.Unmarshal([]byte(cacheEntry), &hashMap)
	if jerr != nil {
		err = fmt.Errorf(err.Error(), funcName)
	}

	return
}

func SaveWAFResourceIDHashMap(s *session.Session, res []resources.GenericResourceExpanded) (err error) {
	funcName := GetFunctionName()

	logrus.Debugf("attempting to save waf resource id hash map from cache")

	var hashMap WAFResourceIDHashMap

	for _, r := range res {
		hash := computeAlder32(*r.ID)

		hashMap.Entries = append(hashMap.Entries, WAFResourceIDHashMapEntry{
			Hash:       hash,
			ResourceID: *r.ID,
		})
	}

	mHashMap, jerr := json.Marshal(hashMap)
	if jerr != nil {
		err = fmt.Errorf(err.Error(), funcName)

		return
	}

	cerr := cache.Write(s, WAFResourceIDHashMapName, string(mHashMap))
	if cerr != nil {
		err = fmt.Errorf(cerr.Error(), funcName)

		return
	}

	return
}

func GetWAFResourceIDFromCacheByHash(s *session.Session, hash string) (resourceID string, err error) {
	funcName := GetFunctionName()

	if s == nil {
		s = session.New()
	}

	s.InitialiseCache()

	hashMap, err := GetWAFResourceIDHashMap(s)
	if err != nil {
		err = fmt.Errorf(err.Error(), funcName)

		return
	}

	if len(hashMap.Entries) == 0 {
		logrus.Debugf("no hashmap entries were loaded")

		return
	}

	for _, entry := range hashMap.Entries {
		if entry.Hash == hash {
			logrus.Debugf("%s | found resource id matching hash %s in cache", funcName, hash)

			return entry.ResourceID, nil
		}
	}

	return
}

type WAFResourceIDHashMapEntry struct {
	Hash       string
	ResourceID string
}

type WAFResourceIDHashMap struct {
	Entries []WAFResourceIDHashMapEntry
}

func GetPolicyResourceIDByHash(s *session.Session, subID, hash string) (resourceID config.ResourceID, err error) {
	// check cache if we have a match
	pID, err := GetWAFResourceIDFromCacheByHash(s, hash)
	if err != nil {
		logrus.Warn(err)
	}

	if pID != "" {
		return config.ParseResourceID(pID), nil
	}

	o, perr := GetAllPolicies(s, GetWrappedPoliciesInput{
		SubscriptionID: subID,
	})
	if perr != nil {
		return resourceID, perr
	}

	if err = SaveWAFResourceIDHashMap(s, o); err != nil {
		return
	}

	for _, p := range o {
		if computeAlder32(*p.ID) == hash {
			pID = *p.ID

			return config.ParseResourceID(pID), nil
		}
	}

	return resourceID, fmt.Errorf("resource with hash %s could not be found", hash)
}

func GetPolicyRIDByHash(s *session.Session, subID, hash string) (pID string, err error) {
	// check cache if we have a match
	pID, err = GetWAFResourceIDFromCacheByHash(s, hash)
	if err != nil {
		logrus.Warn(err)
	}

	if pID != "" {
		return
	}

	o, perr := GetAllPolicies(s, GetWrappedPoliciesInput{
		SubscriptionID: subID,
	})
	if perr != nil {
		return "", perr
	}

	if err = SaveWAFResourceIDHashMap(s, o); err != nil {
		return
	}

	for _, p := range o {
		if computeAlder32(*p.ID) == hash {
			pID = *p.ID

			return
		}
	}

	return pID, fmt.Errorf("resource with hash %s could not be found", hash)
}

type GetWAFPolicyResourceIDInput struct {
	SubscriptionID string
	RawPolicyID    string
	ConfigPath     string
}

func GetWAFPolicyResourceID(s *session.Session, in GetWAFPolicyResourceIDInput) (resourceID config.ResourceID, err error) {
	// try parsing as azure resource id
	resourceID = config.ParseResourceID(in.RawPolicyID)
	if resourceID.Name != "" {
		return resourceID, nil
	}

	// try loading config file to check for policy aliases
	fileConfig, err := config.LoadFileConfig(in.ConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return
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

func GetRawPolicy(s *session.Session, subscription, resourceGroup, name string) (wafPolicy *armfrontdoor.WebApplicationFirewallPolicy, err error) {
	funcName := GetFunctionName()

	err = s.GetFrontDoorPoliciesClient(subscription)
	if err != nil {
		return
	}

	logrus.Debugf("%s | getting AFD Policy %s from subscription %s and resource group %s",
		funcName,
		name,
		subscription,
		resourceGroup)

	logrus.Debugf("getting policy %s from subscription: %s resource group: %s",
		name,
		subscription,
		resourceGroup)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	options := armfrontdoor.PoliciesClientGetOptions{}

	pcg, merr := s.FrontDoorPoliciesClients[subscription].Get(ctx, resourceGroup, name, &options)
	if merr != nil {
		return nil, fmt.Errorf("%s - %s", funcName, merr.Error())
	}

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

type LogIPsInput struct {
	RID      config.ResourceID
	Output   bool
	DryRun   bool
	Filepath string
	Nets     IPNets
	MaxRules int
	Debug    bool
}

type DeleteCustomRulesCLIInput struct {
	BaseCLIInput   BaseCLIInput
	SubscriptionID string
	PolicyID       string
	DryRun         bool
	ConfigPath     string
	RID            config.ResourceID
	Name           string
	NameMatch      *regexp.Regexp
	Priority       string
	MaxRules       int
	Debug          bool
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
	Scope string
}

func GetAllPolicies(s *session.Session, i GetWrappedPoliciesInput) (gres []resources.GenericResourceExpanded, err error) {
	funcName := GetFunctionName()

	err = s.GetResourcesClient(i.SubscriptionID)
	if err != nil {
		return
	}

	ctx := context.Background()

	top := int32(i.Max)
	if i.Max == 0 {
		top = MaxPoliciesToFetch
	}

	logrus.Debugf("listing first %d Policies in Subscription: %s", top, i.SubscriptionID)

	it, merr := s.ResourcesClients[i.SubscriptionID].ListComplete(ctx, "resourceType eq 'Microsoft.Network/frontdoorWebApplicationFirewallPolicies'", "", &top)
	if merr != nil {
		return nil, fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	var total int

	for it.NotDone() {
		if it.Value().ID == nil {
			return nil, fmt.Errorf(fmt.Sprintf("Azure returned a WAF Policy without a resource ID: %+v", it.Value()), funcName)
		}

		// add if filters not provided, or filters are provided, and we have a match

		// TODO: test this
		if len(i.FilterResourceIDs) == 0 || slices.Contains(i.FilterResourceIDs, *it.Value().ID) {
			gres = append(gres, it.Value())
		}

		total++

		// passing top as top number of items isn't working due to an API bug
		// if we have reached top here, then return
		if total == int(top) {
			return
		}

		if merr = it.NextWithContext(ctx); merr != nil {
			return nil, fmt.Errorf("%s - %w", funcName, merr)
		}
	}

	logrus.Debugf("retrieved %d resources", total)

	return gres, err
}

func getResourceIDsFromGenericResources(gres []resources.GenericResourceExpanded) (rids []config.ResourceID) {
	for _, gre := range gres {
		rids = append(rids, config.ParseResourceID(*gre.ID))
	}

	return
}

func GetWrappedPoliciesFromRawIDs(s *session.Session, i GetWrappedPoliciesInput) (o GetWrappedPoliciesOutput, err error) {
	var rids []config.ResourceID

	if len(i.FilterResourceIDs) > 0 {
		for _, rawID := range i.FilterResourceIDs {
			var rid config.ResourceID

			rid, err = GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
				SubscriptionID: i.SubscriptionID,
				RawPolicyID:    rawID,
				ConfigPath:     i.Config,
			})
			if err != nil {
				return o, err
			}

			rids = append(rids, rid)
		}
	} else {
		// retrieve all Policies as generic resources
		var gres []resources.GenericResourceExpanded

		gres, err = GetAllPolicies(s, i)
		if err != nil {
			return
		}

		rids = getResourceIDsFromGenericResources(gres)
	}

	for _, rid := range rids {
		var p *armfrontdoor.WebApplicationFirewallPolicy

		logrus.Debugf("retrieving raw Policy with: %s %s %s", rid.SubscriptionID, rid.ResourceGroup, rid.Name)

		p, err = GetRawPolicy(s, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
		if err != nil {
			return
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

	return
}

// MatchExistingPolicyByID returns the raw Policy matched by the Policy id of its origin, e.g. where the backup was from
func MatchExistingPolicyByID(targetPolicyID string, existingPolicies []WrappedPolicy) (found bool, policy WrappedPolicy) {
	for x := range existingPolicies {
		if strings.EqualFold(existingPolicies[x].PolicyID, targetPolicyID) {
			return true, existingPolicies[x]
		}
	}

	return
}

type WrappedPolicy struct {
	Date           time.Time
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Policy         armfrontdoor.WebApplicationFirewallPolicy
	PolicyID       string
	AppVersion     string
}

type WrappedManagedRuleSet struct {
	Date           time.Time
	SubscriptionID string
	ResourceGroup  string
	Name           string
	ManagedRuleSet armfrontdoor.ManagedRuleSet
	PolicyID       string
	AppVersion     string
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

func GeneratePolicyPatch(i *GeneratePolicyPatchInput) (output GeneratePolicyPatchOutput, err error) {
	funcName := GetFunctionName()

	var originalBytes []byte
	switch v := i.Original.(type) {
	case []byte:
		originalBytes = v
	case armfrontdoor.WebApplicationFirewallPolicy:
		var jerr error

		originalBytes, jerr = json.MarshalIndent(v, "", "    ")
		if jerr != nil {
			return output, fmt.Errorf(jerr.Error(), funcName)
		}
	case WrappedPolicy:
		var jerr error

		originalBytes, jerr = json.MarshalIndent(v.Policy, "", "    ")
		if jerr != nil {
			return output, fmt.Errorf(jerr.Error(), funcName)
		}
	default:
		return output, fmt.Errorf("%s - UnexpectedType %s", funcName, reflect.TypeOf(i.Original).String())
	}

	newPolicyJSON, jerr := json.MarshalIndent(i.New, "", "    ")
	if jerr != nil {
		return output, fmt.Errorf(jerr.Error(), funcName)
	}

	var patch jsondiff.Patch

	patch, jerr = jsondiff.CompareJSON(originalBytes, newPolicyJSON)
	if jerr != nil {
		return output, fmt.Errorf(jerr.Error(), funcName)
	}

	output.TotalDifferences = len(patch)

	for _, op := range patch {
		switch op.Type {
		case "add":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.CustomRuleAdditions++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.ManagedRuleAdditions++
			}
		case "remove":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.CustomRuleRemovals++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.ManagedRuleRemovals++
			}
		case "replace":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.CustomRuleReplacements++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.ManagedRuleReplacements++
			}
		}
	}

	output.CustomRuleChanges = output.CustomRuleAdditions + output.CustomRuleRemovals + output.CustomRuleReplacements
	output.ManagedRuleChanges = output.ManagedRuleAdditions + output.ManagedRuleRemovals + output.ManagedRuleReplacements
	output.TotalRuleDifferences = output.CustomRuleChanges + output.ManagedRuleChanges

	return
}

func ProcessPolicyChanges(input *ProcessPolicyChangesInput) error {
	funcName := GetFunctionName()

	// get existing policy before change to allow for diff and backups
	preChange, err := GetRawPolicy(input.Session, input.SubscriptionID, input.ResourceGroup, input.PolicyName)

	if input.ShowDiff {
		if err = DisplayPolicyDiff(preChange, input.PolicyPostChange); err != nil {
			return fmt.Errorf(err.Error(), funcName)
		}
	}

	if input.DryRun {
		logrus.Infof("%s | changes were not applied as dry-run was requested", funcName)

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
		}, nil, true, false, input.Session.BackupsDir)
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
	})
}
