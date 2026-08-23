package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/logging"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
)

type DeleteManagedRuleExclusionCLIInput struct {
	// BaseCLIInput carries SubscriptionID, ConfigPath and Debug. SubscriptionID
	// and Debug were previously redeclared here, shadowing the embedded copies.
	BaseCLIInput
	// Session optionally provides a pre-configured session; when nil a new
	// one is created. Tests inject a fake-backed session here.
	Session               *session.Session
	PolicyID              string
	RID                   config.ResourceID
	RuleSet               string
	RuleGroup             string
	RuleID                string
	ShowDiff              bool
	ExclusionRuleVariable string
	ExclusionRuleOperator string
	ExclusionRuleSelector string
}

func (input *DeleteCustomRulesCLIInput) ProcessCLIInput() (output DeleteCustomRulesPrefixesInput, err error) {
	output.RID = input.RID
	output.Debug = input.Debug
	output.MaxRules = input.MaxRules

	// if a priority was passed by the cli then convert to int32 and store
	if input.Priority != "" {
		output.Priority, err = strconv.Atoi(input.Priority)
		if err != nil {
			err = fmt.Errorf("priority is invalid")
		}

		output.PrioritySet = true
	}

	if input.Name != "" {
		output.NameMatch = regexp.MustCompile(input.Name)
	}

	return
}

func (input *DeleteManagedRuleExclusionCLIInput) ParseConfig() (dmrei *DeleteManagedRuleExclusionInput, err error) {
	var rsType, rsVersion string
	if input.RuleSet != "" {
		rsType, rsVersion, err = parseRuleSetName(input.RuleSet)
		if err != nil {
			return
		}
	}

	excusionVariable, exclusionOperator, err := NormaliseExclusionInput(input.ExclusionRuleVariable, input.ExclusionRuleOperator)
	if err != nil {
		return
	}

	dmrei = &DeleteManagedRuleExclusionInput{
		DryRun:                input.DryRun,
		ShowDiff:              input.ShowDiff,
		RID:                   input.RID,
		RuleSetType:           &rsType,
		RuleSetVersion:        &rsVersion,
		RuleGroup:             input.RuleGroup,
		RuleID:                input.RuleID,
		ExclusionRuleVariable: excusionVariable,
		ExclusionRuleOperator: exclusionOperator,
		ExclusionRuleSelector: input.ExclusionRuleSelector,
		Debug:                 input.Debug,
	}

	dmrei.Scope, err = GetDeleteManagedRuleExclusionProcessScope(dmrei)

	return dmrei, err
}

func stripFromManagedRuleSet(dcri *DeleteManagedRuleExclusionInput, existingManagedRuleSet *armfrontdoor.ManagedRuleSet) (newMRS *armfrontdoor.ManagedRuleSet, err error) {
	funcName := GetFunctionName()
	// required when running tests without init
	checkDebug(dcri.Debug)
	logging.Tracef("%s | scope: %s", funcName, dcri.Scope)

	if existingManagedRuleSet == nil {
		return nil, fmt.Errorf("%s - managed rule set is missing", funcName)
	}

	newMRS = &armfrontdoor.ManagedRuleSet{}
	newMRS.RuleSetAction = existingManagedRuleSet.RuleSetAction
	newMRS.RuleSetType = existingManagedRuleSet.RuleSetType
	newMRS.RuleSetVersion = existingManagedRuleSet.RuleSetVersion

	switch {
	case dcri.Scope == ScopeRuleSet:
		if !exclusionParamsDefined(dcri) {
			return nil, fmt.Errorf("%s - refusing to delete all exclusions", funcName)
		}

		// only exclusions can be removed at ruleset scope, so propagate remaining attributes
		newMRS.RuleGroupOverrides = existingManagedRuleSet.RuleGroupOverrides
		newMRS.Exclusions = []*armfrontdoor.ManagedRuleExclusion{}

		for _, existingManagedRuleSetExclusion := range existingManagedRuleSet.Exclusions {
			matchRGO := matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
				existingManagedRuleExclusion: existingManagedRuleSetExclusion,
				variable:                     dcri.ExclusionRuleVariable,
				operator:                     dcri.ExclusionRuleOperator,
				selector:                     dcri.ExclusionRuleSelector,
			})

			if !matchRGO {
				newMRS.Exclusions = append(newMRS.Exclusions, existingManagedRuleSetExclusion)
			}
		}

	case strings.EqualFold(dcri.Scope, ScopeRuleGroup):
		for _, existingManagedRuleGroupOverride := range existingManagedRuleSet.RuleGroupOverrides {
			logging.Tracef("%s | checking rule group %s against %s",
				funcName, dcri.RuleGroup, *existingManagedRuleGroupOverride.RuleGroupName)

			if !strings.EqualFold(dcri.RuleGroup, *existingManagedRuleGroupOverride.RuleGroupName) {
				newMRS.RuleGroupOverrides = append(newMRS.RuleGroupOverrides, existingManagedRuleGroupOverride)

				continue
			}

			logging.Tracef("%s | RuleGroupOverride: %s", funcName, valueOrDash(existingManagedRuleGroupOverride.RuleGroupName))

			var strippedManagedRuleGroupOverride *armfrontdoor.ManagedRuleGroupOverride

			strippedManagedRuleGroupOverride, err = stripManagedRuleGroupOverride(dcri, existingManagedRuleGroupOverride)
			if err != nil {
				return nil, err
			}

			newMRS.RuleGroupOverrides = append(newMRS.RuleGroupOverrides, strippedManagedRuleGroupOverride)
		}

		newMRS.Exclusions = existingManagedRuleSet.Exclusions

		preNumRuleGroupOverrides := len(existingManagedRuleSet.RuleGroupOverrides)
		postNumRuleGroupOverrides := len(newMRS.RuleGroupOverrides)

		if preNumRuleGroupOverrides > postNumRuleGroupOverrides {
			logging.Debugf("%s | removed %d %s overrides from ruleset %s_%s",
				funcName,
				preNumRuleGroupOverrides-postNumRuleGroupOverrides,
				dcri.Scope,
				valueOrDash(existingManagedRuleSet.RuleSetType),
				valueOrDash(existingManagedRuleSet.RuleSetVersion))
		}
	case strings.EqualFold(dcri.Scope, ScopeRule):
		for _, existingManagedRuleGroupOverride := range existingManagedRuleSet.RuleGroupOverrides {
			logging.Tracef("%s | RuleGroupOverride: %s", funcName, valueOrDash(existingManagedRuleGroupOverride.RuleGroupName))

			var strippedManagedRuleGroupOverride *armfrontdoor.ManagedRuleGroupOverride

			strippedManagedRuleGroupOverride, err = stripManagedRuleGroupOverride(dcri, existingManagedRuleGroupOverride)
			if err != nil {
				return nil, err
			}

			newMRS.RuleGroupOverrides = append(newMRS.RuleGroupOverrides, strippedManagedRuleGroupOverride)
		}

		newMRS.Exclusions = existingManagedRuleSet.Exclusions

		preNumRuleGroupOverrides := len(existingManagedRuleSet.RuleGroupOverrides)
		postNumRuleGroupOverrides := len(newMRS.RuleGroupOverrides)

		if preNumRuleGroupOverrides > postNumRuleGroupOverrides {
			logging.Debugf("%s | removed %d %s overrides from ruleset %s_%s",
				funcName,
				preNumRuleGroupOverrides-postNumRuleGroupOverrides,
				dcri.Scope,
				valueOrDash(existingManagedRuleSet.RuleSetType),
				valueOrDash(existingManagedRuleSet.RuleSetVersion))
		}
	default:
		return nil, fmt.Errorf("%s - %s %s", funcName, errScopeInvalid, dcri.Scope)
	}

	newMRS.RuleSetType = existingManagedRuleSet.RuleSetType
	newMRS.RuleSetVersion = existingManagedRuleSet.RuleSetVersion

	preExclusionCount := len(existingManagedRuleSet.Exclusions)
	postExclusionCount := len(newMRS.Exclusions)

	if preExclusionCount > postExclusionCount {
		logging.Infof("%s | removed %d exclusions from ruleset %s_%s",
			funcName,
			preExclusionCount-postExclusionCount,
			valueOrDash(existingManagedRuleSet.RuleSetType),
			valueOrDash(existingManagedRuleSet.RuleSetVersion))
	}

	return
}

func exclusionParamsDefined(dcri *DeleteManagedRuleExclusionInput) bool {
	if dcri.ExclusionRuleVariable != "" && dcri.ExclusionRuleOperator != "" && dcri.ExclusionRuleSelector != "" {
		return true
	}

	return false
}

func stripManagedRuleGroupOverrideExclusions(dcri *DeleteManagedRuleExclusionInput, existingManagedRuleExclusions []*armfrontdoor.ManagedRuleExclusion) (newManagedRuleExclusions []*armfrontdoor.ManagedRuleExclusion) {
	funcName := GetFunctionName()

	// return if no exclusions to compare
	if len(existingManagedRuleExclusions) == 0 {
		logging.Debug("no exclusions to compare")
		return existingManagedRuleExclusions
	}

	newManagedRuleExclusions = []*armfrontdoor.ManagedRuleExclusion{}
	// TODO: use-case for this?
	// if no exclusion value operator, variable, nor selector are provided, then remove them all
	// if dcri.exclusionRuleOperator == "" && dcri.exclusionRuleSelector == "" && variable == "" {
	//	logging.Debugf("%s | no exclusion criteria provided so stripping all exclusions", funcName)
	//
	//	return
	// }

	var mRGOE bool

	for _, managedRuleExclusion := range existingManagedRuleExclusions {
		if managedRuleExclusion == nil {
			continue
		}

		mRGOE = matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
			existingManagedRuleExclusion: managedRuleExclusion,
			variable:                     dcri.ExclusionRuleVariable,
			operator:                     dcri.ExclusionRuleOperator,
			selector:                     dcri.ExclusionRuleSelector,
		})

		if mRGOE {
			logging.Debugf("%s | match for exclusion variable: %s operator: %s selector: %s",
				funcName,
				valueOrDash(managedRuleExclusion.MatchVariable),
				valueOrDash(managedRuleExclusion.SelectorMatchOperator),
				valueOrDash(managedRuleExclusion.Selector))

			continue
		}

		logging.Tracef("%s | no match for exclusion %s %s %s",
			funcName,
			valueOrDash(managedRuleExclusion.MatchVariable),
			valueOrDash(managedRuleExclusion.SelectorMatchOperator),
			valueOrDash(managedRuleExclusion.Selector))

		newManagedRuleExclusions = append(newManagedRuleExclusions, managedRuleExclusion)
	}

	return
}

type matchManagedRuleGroupOverrideExclusionInput struct {
	existingManagedRuleExclusion *armfrontdoor.ManagedRuleExclusion
	variable                     armfrontdoor.ManagedRuleExclusionMatchVariable
	operator                     armfrontdoor.ManagedRuleExclusionSelectorMatchOperator
	selector                     string
}

func matchManagedRuleGroupOverrideExclusion(input matchManagedRuleGroupOverrideExclusionInput) (match bool) {
	funcName := GetFunctionName()

	logging.Tracef("comparing my input.Variable: %s with %v", input.variable, valueOrDash(input.existingManagedRuleExclusion.MatchVariable))
	logging.Tracef("comparing my input.Operator: %s with %v", input.operator, valueOrDash(input.existingManagedRuleExclusion.SelectorMatchOperator))
	logging.Tracef("comparing my input.Selector: %s with %s", input.selector, valueOrDash(input.existingManagedRuleExclusion.Selector))

	if input.existingManagedRuleExclusion.MatchVariable == nil || input.variable != *input.existingManagedRuleExclusion.MatchVariable {
		return false
	}

	if input.existingManagedRuleExclusion.SelectorMatchOperator == nil || input.operator != *input.existingManagedRuleExclusion.SelectorMatchOperator {
		return false
	}

	if input.existingManagedRuleExclusion.Selector == nil || input.selector != *input.existingManagedRuleExclusion.Selector {
		return false
	}

	logging.Debugf("%s | returning true", funcName)

	return true
}

// RuleID *string `json:"ruleId,omitempty"`
// Action *ActionType `json:"action,omitempty"`
// EnabledState *ManagedRuleEnabledState `json:"enabledState,omitempty"`
// Exclusions []*ManagedRuleExclusion `json:"exclusions,omitempty"`
// ===
// Return nil if empty
func stripManagedRuleOverride(dcri *DeleteManagedRuleExclusionInput, existingManagedRuleOverride *armfrontdoor.ManagedRuleOverride) (newManagedRuleOverride *armfrontdoor.ManagedRuleOverride) {
	funcName := GetFunctionName()

	if existingManagedRuleOverride == nil {
		return nil
	}

	ruleID := derefOrEmpty(existingManagedRuleOverride.RuleID)

	// if the rule id is provided, and there's no match then return existing (no removal)
	if dcri.RuleID != "" && dcri.RuleID != ruleID {
		return existingManagedRuleOverride
	}

	// if no exclusion details were passed, return matching rule override with all exclusions removed
	if dcri.ExclusionRuleSelector == "" && dcri.ExclusionRuleOperator == "" && dcri.ExclusionRuleVariable == "" {
		logging.Debugf("%s | no exclusion selector, operator, nor variable passed, so return matching rule without exclusions for %s", funcName, ruleID)
		existingManagedRuleOverride.Exclusions = []*armfrontdoor.ManagedRuleExclusion{}

		return existingManagedRuleOverride
	}

	// exclusions were passed, so remove any matching
	logging.Debugf("%s | exclusion selector, operator, and variable passed, so return matching rule stripped exclusions for %s", funcName, ruleID)

	preExclusionCount := len(existingManagedRuleOverride.Exclusions)

	existingManagedRuleOverride.Exclusions = stripManagedRuleGroupOverrideExclusions(dcri, existingManagedRuleOverride.Exclusions)

	// report if any exclusions have been removed
	if preExclusionCount != len(existingManagedRuleOverride.Exclusions) {
		logging.Debugf("%s | removed %d exclusions from rule %s", funcName, preExclusionCount-len(existingManagedRuleOverride.Exclusions), ruleID)
	}

	return existingManagedRuleOverride
}

// If rule id only, then drop specific or all (if no exclusion vals in req) exclusions from the rule

// RuleID *string `json:"ruleId,omitempty"`
// Action *ActionType `json:"action,omitempty"`
// EnabledState *ManagedRuleEnabledState `json:"enabledState,omitempty"`
// Exclusions []*ManagedRuleExclusion `json:"exclusions,omitempty"`
// ===
// Return nil if empty
func stripManagedRuleGroupOverrideRules(dcri *DeleteManagedRuleExclusionInput, existingManagedRuleGroupOverrides []*armfrontdoor.ManagedRuleOverride) (newManagedRuleGroupOverrides []*armfrontdoor.ManagedRuleOverride) {
	funcName := GetFunctionName()

	newManagedRuleGroupOverrides = []*armfrontdoor.ManagedRuleOverride{}

	for _, existingManagedRuleOverride := range existingManagedRuleGroupOverrides {
		existingManagedRuleOverride := existingManagedRuleOverride
		if existingManagedRuleOverride == nil {
			continue
		}

		preExclusionsCount := len(existingManagedRuleOverride.Exclusions)
		ruleID := derefOrEmpty(existingManagedRuleOverride.RuleID)

		logging.Tracef(
			"%s | %s with %d exclusions",
			funcName,
			ruleID,
			len(existingManagedRuleOverride.Exclusions),
		)

		// remove matching exclusions from the rule
		newManagedRuleOverride := stripManagedRuleOverride(dcri, existingManagedRuleOverride)

		// TODO: output changes if any made

		// if we got a result, append it as it means no changes were necessary, or an update was made
		// the count comparison below reads through it, so it has to stay inside this check
		if newManagedRuleOverride == nil {
			continue
		}

		newManagedRuleGroupOverrides = append(newManagedRuleGroupOverrides, newManagedRuleOverride)

		postExclusionsCount := len(newManagedRuleOverride.Exclusions)
		if preExclusionsCount > postExclusionsCount {
			logging.Infof(
				"removing %d exclusions from override rule %s",
				preExclusionsCount-postExclusionsCount,
				ruleID,
			)
		}
	}

	return
}

func stripManagedRuleGroupOverride(dcri *DeleteManagedRuleExclusionInput, existingManagedRuleGroupOverride *armfrontdoor.ManagedRuleGroupOverride) (newManagedRuleGroupOverride *armfrontdoor.ManagedRuleGroupOverride, err error) {
	funcName := GetFunctionName()

	if existingManagedRuleGroupOverride == nil {
		return nil, fmt.Errorf("%s - rule group override is missing", funcName)
	}

	newManagedRuleGroupOverride = &armfrontdoor.ManagedRuleGroupOverride{
		Exclusions: []*armfrontdoor.ManagedRuleExclusion{},
		Rules:      nil,
	}

	newManagedRuleGroupOverride.RuleGroupName = existingManagedRuleGroupOverride.RuleGroupName

	// only remove from rule group if rule isn't specified
	// OR neither rule group nor rule are specified and an exclusion variable has been set
	var newManagedRuleGroupOverrideExclusions []*armfrontdoor.ManagedRuleExclusion

	switch dcri.Scope {
	case ScopeRuleGroup:
		// strip exclusions directly from rule group
		newManagedRuleGroupOverrideExclusions = stripManagedRuleGroupOverrideExclusions(dcri, existingManagedRuleGroupOverride.Exclusions)

		// report if we removed any
		if len(newManagedRuleGroupOverrideExclusions) != len(existingManagedRuleGroupOverride.Exclusions) {
			logging.Debugf("%s | removed %d exclusions from %s", funcName, len(existingManagedRuleGroupOverride.Exclusions)-len(newManagedRuleGroupOverrideExclusions), *existingManagedRuleGroupOverride.RuleGroupName)
		}

		newManagedRuleGroupOverride.Exclusions = newManagedRuleGroupOverrideExclusions
		newManagedRuleGroupOverride.Rules = existingManagedRuleGroupOverride.Rules
	case ScopeRule:
		// strip exclusions from rules within the group
		var newManagedRuleGroupOverrideRules []*armfrontdoor.ManagedRuleOverride
		newManagedRuleGroupOverrideRules = stripManagedRuleGroupOverrideRules(dcri, existingManagedRuleGroupOverride.Rules)
		// report if we removed any
		if len(newManagedRuleGroupOverrideRules) != len(existingManagedRuleGroupOverride.Rules) {
			logging.Debugf("%s | removed %d group override rules from %s", funcName, len(existingManagedRuleGroupOverride.Rules)-len(newManagedRuleGroupOverrideRules), *existingManagedRuleGroupOverride.RuleGroupName)
		}

		if err != nil {
			return
		}

		newManagedRuleGroupOverride.Rules = newManagedRuleGroupOverrideRules
		// maintain existing ruleg group override exclusions
		newManagedRuleGroupOverride.Exclusions = existingManagedRuleGroupOverride.Exclusions
	default:
		return nil, fmt.Errorf("%s - %s %s", funcName, errScopeInvalid, dcri.Scope)
	}

	return
}

func stripMatchingMREs(dcri *DeleteManagedRuleExclusionInput, existingMRSList *armfrontdoor.ManagedRuleSetList) (newMRSList *armfrontdoor.ManagedRuleSetList, err error) {
	funcName := GetFunctionName()

	newMRSList = &armfrontdoor.ManagedRuleSetList{}
	newMRSList.ManagedRuleSets = []*armfrontdoor.ManagedRuleSet{}

	if existingMRSList == nil {
		return newMRSList, nil
	}

	// walk through ruleset lists, building a new set based on user provided matches
	for x := range existingMRSList.ManagedRuleSets {
		if existingMRSList.ManagedRuleSets[x] == nil {
			continue
		}

		// create a new Managed rule set that'll mirror the existing, minus the MREs
		logging.Debugf("stripping from ruleset %s_%s",
			derefOrEmpty(existingMRSList.ManagedRuleSets[x].RuleSetType),
			derefOrEmpty(existingMRSList.ManagedRuleSets[x].RuleSetVersion))

		var strippedMRS *armfrontdoor.ManagedRuleSet

		strippedMRS, err = stripFromManagedRuleSet(dcri, existingMRSList.ManagedRuleSets[x])
		if err != nil {
			return nil, err
		}

		if strippedMRS == nil {
			logging.Errorf("%s | stripped Managed rule set %s_%s is nil", funcName, *existingMRSList.ManagedRuleSets[x].RuleSetType, *existingMRSList.ManagedRuleSets[x].RuleSetVersion)
		}

		newMRSList.ManagedRuleSets = append(newMRSList.ManagedRuleSets, strippedMRS)
	}

	// debug check we've not done something silly
	if len(newMRSList.ManagedRuleSets) != len(existingMRSList.ManagedRuleSets) {
		return nil, fmt.Errorf("%s - removed a ruleset - oops", funcName)
	}

	return
}

func DeleteManagedRuleExclusion(dmreci *DeleteManagedRuleExclusionCLIInput) (err error) {
	s := dmreci.Session
	if s == nil {
		if s, err = session.New(); err != nil {
			return err
		}
	}

	s.AppVersion = dmreci.AppVersion

	// resolve the policy name through the shared resolver so that aliases,
	// hashes and full resource ids all work, as they do for add exclusion
	rid, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: dmreci.SubscriptionID,
		RawPolicyID:    dmreci.PolicyID,
		ConfigPath:     dmreci.ConfigPath,
	})
	if err != nil {
		return err
	}

	dmreci.RID = rid

	dmrei, err := dmreci.ParseConfig()
	if err != nil {
		return
	}

	var p *armfrontdoor.WebApplicationFirewallPolicy

	subscription := dmrei.RID.SubscriptionID
	resourceGroup := dmrei.RID.ResourceGroup
	name := dmrei.RID.Name

	// check if Policy exists
	p, err = GetRawPolicy(s, subscription, resourceGroup, name)
	if err != nil {
		return err
	}

	// get copy of policy for later comparison
	original, err := CopyPolicy(*p)
	if err != nil {
		return
	}

	updatedMRSL, err := stripMatchingMREs(dmrei, policyManagedRuleSetList(p))
	if err != nil {
		logging.Error(err.Error())
	}

	p.Properties.ManagedRules = updatedMRSL

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: original,
		New:      *p,
	})

	if patch.TotalDifferences == 0 {
		logging.Debug("nothing to do")

		return
	}

	if patch.CustomRuleChanges != 0 {
		logging.Errorf("unexpected custom rules changes. aborting")

		return
	}

	return ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       *p.Name,
		ShowDiff:         dmreci.ShowDiff,
		SubscriptionID:   subscription,
		ResourceGroup:    resourceGroup,
		PolicyPostChange: *p,
		DryRun:           dmreci.DryRun,
		Debug:            dmreci.Debug,
		Backup:           dmreci.AutoBackup,
	})
}

type ProcessPolicyChangesInput struct {
	Session          *session.Session
	PolicyName       string
	SubscriptionID   string
	ResourceGroup    string
	PolicyPostChange armfrontdoor.WebApplicationFirewallPolicy
	ShowDiff         bool
	DryRun           bool
	Backup           bool
	Debug            bool
	// Async pushes the policy without waiting for the operation to complete.
	Async bool
}
