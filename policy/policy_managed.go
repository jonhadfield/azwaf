package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
)

func getRuleGroupExclusionsFromRuleSet(ruleGroup string, ruleSet *armfrontdoor.ManagedRuleSet) (groupEx []*armfrontdoor.ManagedRuleExclusion) {
	for _, ruleGroupOverride := range ruleSetGroupOverrides(ruleSet) {
		ruleGroupOverride := ruleGroupOverride
		if ruleGroupOverride == nil || ruleGroupOverride.RuleGroupName == nil {
			continue
		}

		if strings.EqualFold(ruleGroup, *ruleGroupOverride.RuleGroupName) {
			groupEx = ruleGroupOverride.Exclusions

			return
		}
	}

	return nil
}

// getAllExclusionsByRuleID returns all of the rule set and rule group exclusions that would be inherited by the rule
func getAllExclusionsByRuleID(ruleID string, ruleSet *armfrontdoor.ManagedRuleSet) (ruleEx, groupEx, setEx []*armfrontdoor.ManagedRuleExclusion) {
	setEx = ruleSetExclusions(ruleSet)

	for _, ruleGroupOverride := range ruleSetGroupOverrides(ruleSet) {
		ruleGroupOverride := ruleGroupOverride
		groupEx = groupOverrideExclusions(ruleGroupOverride)

		for _, rule := range groupOverrideRules(ruleGroupOverride) {
			rule := rule
			if rule == nil || rule.RuleID == nil {
				continue
			}

			if *rule.RuleID == ruleID {
				ruleEx = rule.Exclusions

				return
			}
		}
	}

	return nil, nil, nil
}

type getDefinitionsMatchingExistingRuleSetsInput struct {
	mrsdl          []*armfrontdoor.ManagedRuleSetDefinition
	mrsl           *armfrontdoor.ManagedRuleSetList
	ruleID         string
	groupName      string
	ruleSetType    string
	ruleSetVersion string
}

type getMatchingDefinitionsOutput struct {
	RuleSetDefinition   *armfrontdoor.ManagedRuleSetDefinition
	RuleGroupDefinition *armfrontdoor.ManagedRuleGroupDefinition
	RuleDefinition      *armfrontdoor.ManagedRuleDefinition
}

type getMatchingDefaultDefinitionsInput struct {
	mrsdl          []*armfrontdoor.ManagedRuleSetDefinition
	ruleID         string
	groupName      string
	ruleSetType    string
	ruleSetVersion string
}

type getMatchingDefaultDefinitionsOutput struct {
	RuleSetDefinition   *armfrontdoor.ManagedRuleSetDefinition
	RuleGroupDefinition *armfrontdoor.ManagedRuleGroupDefinition
	RuleDefinition      *armfrontdoor.ManagedRuleDefinition
}

// getMatchingDefaultDefinitions returns the API's default definitions of the given rule, rule group, and/or rule set provided
func getMatchingDefaultDefinitions(input *getMatchingDefaultDefinitionsInput) (output getMatchingDefaultDefinitionsOutput, err error) {
	funcName := helpers.GetFunctionName()

	//  ruleset details are required
	if input.ruleSetType == "" || input.ruleSetVersion == "" {
		return output, fmt.Errorf("%s - rule set type and version are required to match default definitions", funcName)
	}

	for _, ruleSetDefinition := range input.mrsdl {
		ruleSetDefinition := ruleSetDefinition

		output.RuleSetDefinition = ruleSetDefinition
		// if rule set doesn't match this definition, then move on
		logging.Tracef("%s | comparing %s %s with %s %s", input.ruleSetType,
			*ruleSetDefinition.Properties.RuleSetType, input.ruleSetVersion,
			*ruleSetDefinition.Properties.RuleSetVersion, funcName)

		if !strings.EqualFold(input.ruleSetType, *ruleSetDefinition.Properties.RuleSetType) || !strings.EqualFold(input.ruleSetVersion, *ruleSetDefinition.Properties.RuleSetVersion) {
			continue
		}

		// if neither rule group nor rule id provided, then return matching ruleset
		if input.groupName == "" && input.ruleID == "" {
			return
		}

		for _, ruleGroupDefinition := range ruleSetDefinition.Properties.RuleGroups {
			ruleGroupDefinition := ruleGroupDefinition

			output.RuleGroupDefinition = ruleGroupDefinition

			if strings.EqualFold(input.groupName, *ruleGroupDefinition.RuleGroupName) && input.ruleID == "" {
				// if only group is needed, then return
				return
			}

			for _, ruleDefinition := range ruleGroupDefinition.Rules {
				ruleDefinition := ruleDefinition
				output.RuleDefinition = ruleDefinition

				if input.ruleID == *ruleDefinition.RuleID {
					return
				}
			}
		}
	}

	// no match: not an error, the callers report the specific miss
	return getMatchingDefaultDefinitionsOutput{
		RuleSetDefinition:   nil,
		RuleGroupDefinition: nil,
		RuleDefinition:      nil,
	}, nil
}

type getDefinitionsMatchingExistingRuleSetInput struct {
	scope          ExclusionScope
	mrsd           *armfrontdoor.ManagedRuleSetDefinition
	ruleID         string
	groupName      string
	ruleSetType    string
	ruleSetVersion string
}

// match early option indicates if we should match on ruleset type and version if supplied
func getDefinitionMatchingExistingRuleSet(input *getDefinitionsMatchingExistingRuleSetInput) (match bool, output getMatchingDefinitionsOutput, err error) {
	funcName := helpers.GetFunctionName()
	if input.scope == "" {
		return false, output, fmt.Errorf("%s - scope must be provided", funcName)
	}

	if input.mrsd == nil || input.mrsd.Properties == nil {
		return false, output, fmt.Errorf("%s - rule set definition is missing", funcName)
	}

	// we can set this early as a scope specific match with determine success
	output.RuleSetDefinition = input.mrsd

	defType := derefOrEmpty(input.mrsd.Properties.RuleSetType)
	defVersion := derefOrEmpty(input.mrsd.Properties.RuleSetVersion)

	if input.scope == ScopeRuleSet && strings.EqualFold(defType, input.ruleSetType) && strings.EqualFold(defVersion, input.ruleSetVersion) {
		logging.Tracef("%s | comparing %s %s with %s %s", funcName, defType, input.ruleSetType, defVersion, input.ruleSetVersion)

		// if we match rule set input, then return
		// * rule set input only specified if that's all that's needed
		return true, output, err
	}

	for _, ruleGroupDefinition := range input.mrsd.Properties.RuleGroups {
		ruleGroupDefinition := ruleGroupDefinition

		output.RuleGroupDefinition = ruleGroupDefinition

		if ruleGroupDefinition == nil {
			continue
		}

		if input.scope == ScopeRuleGroup && strings.EqualFold(input.groupName, derefOrEmpty(ruleGroupDefinition.RuleGroupName)) {
			// if only group is needed, then return
			return true, output, err
		}

		for _, ruleDefinition := range ruleGroupDefinition.Rules {
			ruleDefinition := ruleDefinition

			output.RuleDefinition = ruleDefinition
			if input.ruleID == *ruleDefinition.RuleID {
				return true, output, err
			}
		}
	}

	return
}

func GetRuleSetDefinitionsMatchingPolicy(s *session.Session, policy *armfrontdoor.WebApplicationFirewallPolicy) (rsds []*armfrontdoor.ManagedRuleSetDefinition, err error) {
	funcName := helpers.GetFunctionName()

	if policy == nil {
		return rsds, fmt.Errorf("%s - policy not provided", funcName)
	}

	if policy.ID == nil {
		return rsds, fmt.Errorf("%s - policy id missing", funcName)
	}

	rid := config.ParseResourceID(*policy.ID)

	allRuleSetDefs, err := getRuleSetDefinitions(s, rid.SubscriptionID)
	if err != nil {
		return
	}

	if ok, _ := HasRuleSets(policy); !ok {
		err = fmt.Errorf("%s - policy has no rulesets associated", funcName)

		return
	}

	for _, ruleSet := range policyManagedRuleSets(policy) {
		ruleSet := ruleSet
		if ok, mrsd := getRuleSetDefinitionMatchingRuleSetTypeVersion(allRuleSetDefs, *ruleSet.RuleSetType, *ruleSet.RuleSetVersion); ok {
			rsds = append(rsds, mrsd)
		}
	}

	return
}

func getRuleSetDefinitionMatchingRuleSetTypeVersion(rsds []*armfrontdoor.ManagedRuleSetDefinition, ruleSetType, ruleSetVersion string) (match bool, mrsd *armfrontdoor.ManagedRuleSetDefinition) {
	for x := range rsds {
		if rsds[x] == nil || rsds[x].Properties == nil {
			continue
		}

		if derefOrEmpty(rsds[x].Properties.RuleSetType) == ruleSetType &&
			derefOrEmpty(rsds[x].Properties.RuleSetVersion) == ruleSetVersion {
			return true, rsds[x]
		}
	}

	return false, nil
}

func getDefinitionsMatchingGroupName(s *session.Session, policy *armfrontdoor.WebApplicationFirewallPolicy, groupName, ruleSetType, ruleSetVersion string) (matchingDefinitions getMatchingDefaultDefinitionsOutput, err error) {
	funcName := helpers.GetFunctionName()

	if groupName == "" {
		err = fmt.Errorf("%s - rule group name not passed", funcName)
		return
	}

	matchingRuleSetDefinitions, err := GetRuleSetDefinitionsMatchingPolicy(s, policy)
	if err != nil {
		return
	}

	// get policy associated rule set matching the requested rule set, rule group, or rule identifiers
	matchingDefinitions, err = getMatchingDefaultDefinitions(&getMatchingDefaultDefinitionsInput{
		mrsdl:          matchingRuleSetDefinitions,
		ruleSetType:    ruleSetType,
		ruleSetVersion: ruleSetVersion,
		groupName:      groupName,
	})
	if err != nil {
		return
	}

	if matchingDefinitions.RuleGroupDefinition == nil {
		err = fmt.Errorf("%s - group definition %s not found", funcName, groupName)
	}

	return
}

func getDefinitionsMatchingRuleID(s *session.Session, policy *armfrontdoor.WebApplicationFirewallPolicy, ruleID, ruleSetType, ruleSetVersion string) (matchingDefinitions getMatchingDefaultDefinitionsOutput, err error) {
	funcName := helpers.GetFunctionName()

	if ruleID == "" {
		err = fmt.Errorf("%s - rule id not passed", funcName)
		return
	}

	matchingRuleSetDefinitions, err := GetRuleSetDefinitionsMatchingPolicy(s, policy)
	if err != nil {
		return
	}

	// get policy associated rule set matching the requested rule set, rule group, or rule identifiers
	matchingDefinitions, err = getMatchingDefaultDefinitions(&getMatchingDefaultDefinitionsInput{
		mrsdl:          matchingRuleSetDefinitions,
		ruleSetType:    ruleSetType,
		ruleSetVersion: ruleSetVersion,
		ruleID:         ruleID,
	})
	if err != nil {
		return
	}

	if matchingDefinitions.RuleDefinition == nil {
		err = fmt.Errorf("%s - rule definition for %s not found", funcName, ruleID)
	}

	return
}

// TODO: return error if more than one of the following is entered: ruleid, groupid, type+version
// getDefinitionMatchingExistingRuleSets returns the API's default definitions of the given rule, rule group, and/or rule set provided
// provided identifiers must exist in existing ruleset
func getDefinitionMatchingExistingRuleSets(input *getDefinitionsMatchingExistingRuleSetsInput) (output *getMatchingDefinitionsOutput) {
	output = &getMatchingDefinitionsOutput{}

	for _, ruleSetDefinition := range input.mrsdl {
		ruleSetDefinition := ruleSetDefinition
		output.RuleSetDefinition = ruleSetDefinition

		match, res, err := getDefinitionMatchingExistingRuleSet(&getDefinitionsMatchingExistingRuleSetInput{
			scope:          ScopeRuleSet,
			mrsd:           ruleSetDefinition,
			ruleID:         input.ruleID,
			groupName:      input.groupName,
			ruleSetType:    input.ruleSetType,
			ruleSetVersion: input.ruleSetVersion,
		})
		if err != nil {
			logging.Error(err.Error())
		}

		if match {
			output.RuleGroupDefinition = res.RuleGroupDefinition
			output.RuleDefinition = res.RuleDefinition

			return
		}
	}

	return &getMatchingDefinitionsOutput{
		RuleSetDefinition:   nil,
		RuleGroupDefinition: nil,
		RuleDefinition:      nil,
	}
}

type ShowExclusionsCLIInput struct {
	BaseCLIInput
	SubscriptionID string
	PolicyID       string
	RuleSet        string
	RuleGroup      string
	RuleID         string
	Shadows        bool
}

func (input *ShowExclusionsCLIInput) Validate() error {
	return commonCLIInputValidation(input.SubscriptionID, input.PolicyID)
}

func ShowExclusions(in *ShowExclusionsCLIInput) error {
	funcName := helpers.GetFunctionName()

	logging.Tracef("%s showing exclusions", funcName)

	s, err := session.New()
	if err != nil {
		return err
	}

	policyID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: in.SubscriptionID,
		RawPolicyID:    in.PolicyID,
		ConfigPath:     in.ConfigPath,
	})
	if err != nil {
		return err
	}

	switch {
	case in.RuleID != "":
		return ShowManagedRuleExclusions(in.RuleID, policyID)
	case in.RuleGroup != "":
		return ShowManagedRuleGroupExclusions(in.RuleGroup, policyID)
	case in.RuleSet != "":
		var rsType string

		var rsVersion string

		rsType, rsVersion, err = parseRuleSetName(in.RuleSet)
		if err != nil {
			return err
		}

		return ShowManagedRuleSetExclusions(rsType, rsVersion, policyID)
	}

	return nil
}

type getMatchingRuleSetInput struct {
	RuleSetList    *armfrontdoor.ManagedRuleSetList
	ruleSetType    string
	ruleSetVersion string
	RuleGroup      string
	RuleID         string
}

func getMatchingRuleSet(input getMatchingRuleSetInput) (ruleSet *armfrontdoor.ManagedRuleSet, found bool) {
	for _, rs := range ruleSetListSets(input.RuleSetList) {
		rs := rs
		if rs == nil {
			continue
		}

		if input.ruleSetType == derefOrEmpty(rs.RuleSetType) && input.ruleSetVersion == derefOrEmpty(rs.RuleSetVersion) {
			return rs, true
		}

		for _, ruleGroup := range ruleSetGroupOverrides(rs) {
			ruleGroup := ruleGroup

			if strings.EqualFold(input.RuleGroup, derefOrEmpty(ruleGroup.RuleGroupName)) {
				return rs, true
			}

			for _, rule := range groupOverrideRules(ruleGroup) {
				rule := rule

				if input.RuleID == derefOrEmpty(rule.RuleID) {
					return rs, true
				}
			}
		}
	}

	return nil, false
}

func ShowManagedRuleExclusions(ruleID string, policyID config.ResourceID) error {
	funcName := helpers.GetFunctionName()

	s, err := session.New()
	if err != nil {
		return err
	}

	getPolicyInput := GetPolicyInput{
		Session:  s,
		PolicyID: policyID,
		// SubscriptionID: subID,
	}

	getPolicyOutput, err := getPolicyInput.GetPolicy()
	if err != nil {
		return err
	}

	if ok, _ := HasRuleSets(getPolicyOutput.Policy); !ok {
		return fmt.Errorf("%s - policy has no rule sets", funcName)
	}

	// get policy associated rule set matching the requested rule set, rule group, or rule identifiers
	matchingRuleSet, found := getMatchingRuleSet(getMatchingRuleSetInput{
		RuleSetList: policyManagedRuleSetList(getPolicyOutput.Policy),
		RuleID:      ruleID,
	})
	if !found {
		return fmt.Errorf("%s - rule with id %s has no directly assigned exclusions in associated rule sets",
			funcName, ruleID)
	}

	// get rule definition
	matchingDefinitions, err := getDefinitionsMatchingRuleID(s, getPolicyOutput.Policy, ruleID, *matchingRuleSet.RuleSetType, *matchingRuleSet.RuleSetVersion)
	if err != nil {
		return err
	}

	// get all exclusions for the given rule's group and set
	_, ruleGroupEx, ruleSetEx := getAllExclusionsByRuleID(ruleID, matchingRuleSet)

	gmro := getManagedRule(getManagedRuleInput{
		ruleID:             ruleID,
		managedRuleSetList: policyManagedRuleSetList(getPolicyOutput.Policy),
	})

	OutputManagedRuleExclusions(&OutputManagedRuleInput{
		Policy:              getPolicyOutput.Policy,
		PolicyName:          valueOrDash(getPolicyOutput.Policy.Name),
		RuleGroupExclusions: ruleGroupEx,
		RuleSetExclusions:   ruleSetEx,
		Rule:                gmro.managedRuleOverride,
		RuleSetDefinition:   matchingDefinitions.RuleSetDefinition,
		RuleGroupDefinition: matchingDefinitions.RuleGroupDefinition,
		RuleDefinition:      matchingDefinitions.RuleDefinition,
	})

	return nil
}

func ShowManagedRuleGroupExclusions(ruleGroup string, policyID config.ResourceID) error {
	funcName := helpers.GetFunctionName()

	s, err := session.New()
	if err != nil {
		return err
	}

	getPolicyInput := GetPolicyInput{
		Session:  s,
		PolicyID: policyID,
		// SubscriptionID: subID,
	}

	getPolicyOutput, err := getPolicyInput.GetPolicy()
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	// get policy associated rule set matching the requested rule set, rule group, or rule identifiers
	matchingRuleSet, found := getMatchingRuleSet(getMatchingRuleSetInput{
		RuleSetList: policyManagedRuleSetList(getPolicyOutput.Policy),
		RuleGroup:   ruleGroup,
	})
	if !found {
		return fmt.Errorf("%s - failed to find rule group %s in associated rule sets", funcName, ruleGroup)
	}

	matchingDefinitions, err := getDefinitionsMatchingGroupName(s, getPolicyOutput.Policy, ruleGroup, *matchingRuleSet.RuleSetType, *matchingRuleSet.RuleSetVersion)
	if err != nil {
		return err
	}

	ruleGroupEx := getRuleGroupExclusionsFromRuleSet(ruleGroup, matchingRuleSet)

	OutputManagedRuleGroupExclusions(&OutputManagedRuleInput{
		Policy:              getPolicyOutput.Policy,
		PolicyName:          valueOrDash(getPolicyOutput.Policy.Name),
		RuleGroupExclusions: ruleGroupEx,
		RuleSetExclusions:   matchingRuleSet.Exclusions,
		RuleSetDefinition:   matchingDefinitions.RuleSetDefinition,
		RuleGroupDefinition: matchingDefinitions.RuleGroupDefinition,
		RuleDefinition:      matchingDefinitions.RuleDefinition,
	})

	return nil
}

type shadow struct {
	shadowType  ExclusionScope
	shadowName  string
	shadowsType ExclusionScope
	shadowsName string
	exclusion   *armfrontdoor.ManagedRuleExclusion
}

func getShadowsFromRuleSet(ruleSet *armfrontdoor.ManagedRuleSet) (ruleShadows, groupShadows []shadow) {
	if ruleSet == nil {
		return nil, nil
	}

	// loop through each rule group
	for x := range ruleSet.RuleGroupOverrides {
		if ruleSet.RuleGroupOverrides[x] == nil {
			continue
		}

		// loop through each rule
		for y := range ruleSet.RuleGroupOverrides[x].Rules {
			if ruleSet.RuleGroupOverrides[x].Rules[y] == nil {
				continue
			}

			// loop through each rules exclusions
			for y1 := range ruleSet.RuleGroupOverrides[x].Rules[y].Exclusions {
				// loop through each rule groups exclusions
				for y2 := range ruleSet.RuleGroupOverrides[x].Exclusions {
					if HasMatchingExclusions(ruleSet.RuleGroupOverrides[x].Exclusions[y2],
						ruleSet.RuleGroupOverrides[x].Rules[y].Exclusions[y1]) {
						// check if exclusions match
						ruleShadows = append(ruleShadows, shadow{
							shadowType:  ScopeRule,
							shadowName:  derefOrEmpty(ruleSet.RuleGroupOverrides[x].Rules[y].RuleID),
							shadowsType: ScopeRuleGroup,
							shadowsName: derefOrEmpty(ruleSet.RuleGroupOverrides[x].RuleGroupName),
							exclusion:   ruleSet.RuleGroupOverrides[x].Exclusions[y2],
						})
					}
				}
				// match rule exclusions against rule set exclusions
				for x2 := range ruleSet.Exclusions {
					if HasMatchingExclusions(ruleSet.RuleGroupOverrides[x].Rules[y].Exclusions[y1], ruleSet.Exclusions[x2]) {
						ruleShadows = append(ruleShadows, shadow{
							shadowType:  ScopeRule,
							shadowName:  derefOrEmpty(ruleSet.RuleGroupOverrides[x].Rules[y].RuleID),
							shadowsType: ScopeRuleSet,
							shadowsName: fmt.Sprintf("%s_%s", derefOrEmpty(ruleSet.RuleSetType), derefOrEmpty(ruleSet.RuleSetVersion)),
							exclusion:   ruleSet.Exclusions[x2],
						})
					}
				}
			}
		}

		for x1 := range ruleSet.RuleGroupOverrides[x].Exclusions {
			// match rule group exclusions against rule set exclusions
			for x2 := range ruleSet.Exclusions {
				if HasMatchingExclusions(ruleSet.RuleGroupOverrides[x].Exclusions[x1], ruleSet.Exclusions[x2]) {
					groupShadows = append(groupShadows, shadow{
						shadowType:  ScopeRuleGroup,
						shadowName:  derefOrEmpty(ruleSet.RuleGroupOverrides[x].RuleGroupName),
						shadowsType: ScopeRuleSet,
						shadowsName: fmt.Sprintf("%s_%s", derefOrEmpty(ruleSet.RuleSetType), derefOrEmpty(ruleSet.RuleSetVersion)),
						exclusion:   ruleSet.Exclusions[x2],
					})
				}
			}
		}
	}

	return
}

func HasMatchingExclusions(one, two *armfrontdoor.ManagedRuleExclusion) bool {
	if one == nil || two == nil {
		return false
	}

	if one.MatchVariable == nil || two.MatchVariable == nil || (*one.MatchVariable != *two.MatchVariable) {
		return false
	}

	if one.SelectorMatchOperator == nil || two.SelectorMatchOperator == nil || (*one.SelectorMatchOperator != *two.SelectorMatchOperator) {
		return false
	}

	if one.Selector == nil || two.Selector == nil || (*one.Selector != *two.Selector) {
		return false
	}

	return true
}

func ShowManagedRuleSetExclusions(ruleSetType, ruleSetVersion string, policyID config.ResourceID) error {
	funcName := helpers.GetFunctionName()

	s, err := session.New()
	if err != nil {
		return err
	}
	getPolicyInput := GetPolicyInput{
		Session:  s,
		PolicyID: policyID,
	}

	getPolicyOutput, err := getPolicyInput.GetPolicy()
	if err != nil {
		return err
	}

	if ok, _ := HasRuleSets(getPolicyOutput.Policy); !ok {
		return fmt.Errorf("%s - policy has no rule sets", funcName)
	}

	matchingRuleSet, found := getMatchingRuleSet(getMatchingRuleSetInput{
		RuleSetList:    policyManagedRuleSetList(getPolicyOutput.Policy),
		ruleSetType:    ruleSetType,
		ruleSetVersion: ruleSetVersion,
	})
	if !found {
		return fmt.Errorf("%s - rule set with type %s and version %s not associated with this policy",
			funcName, ruleSetType, ruleSetVersion)
	}

	definitionsMatchingPolicy, err := GetRuleSetDefinitionsMatchingPolicy(s, getPolicyOutput.Policy)
	if err != nil {
		return fmt.Errorf("%s - policy definitions not found", funcName)
	}

	// get set definition
	matchingDefinitions := getDefinitionMatchingExistingRuleSets(&getDefinitionsMatchingExistingRuleSetsInput{
		mrsdl:          definitionsMatchingPolicy,
		mrsl:           policyManagedRuleSetList(getPolicyOutput.Policy),
		ruleSetType:    ruleSetType,
		ruleSetVersion: ruleSetVersion,
	})

	if matchingDefinitions.RuleSetDefinition == nil {
		return fmt.Errorf("%s - rule set %s_%s does not exist",
			funcName,
			ruleSetType,
			ruleSetVersion)
	}

	OutputManagedRuleSetExclusions(&OutputManagedRuleInput{
		Policy:              getPolicyOutput.Policy,
		PolicyName:          valueOrDash(getPolicyOutput.Policy.Name),
		RuleSetExclusions:   matchingRuleSet.Exclusions,
		RuleSetDefinition:   matchingDefinitions.RuleSetDefinition,
		RuleGroupDefinition: matchingDefinitions.RuleGroupDefinition,
		RuleDefinition:      matchingDefinitions.RuleDefinition,
	})

	return nil
}

type OutputManagedRuleInput struct {
	Policy              *armfrontdoor.WebApplicationFirewallPolicy
	PolicyName          string
	Rule                *armfrontdoor.ManagedRuleOverride
	RuleGroupExclusions []*armfrontdoor.ManagedRuleExclusion
	RuleSetExclusions   []*armfrontdoor.ManagedRuleExclusion
	RuleSetDefinition   *armfrontdoor.ManagedRuleSetDefinition
	RuleGroupDefinition *armfrontdoor.ManagedRuleGroupDefinition
	RuleDefinition      *armfrontdoor.ManagedRuleDefinition
}

func getRuleSetDefinitions(s *session.Session, subID string) (rsds []*armfrontdoor.ManagedRuleSetDefinition, err error) {
	// TODO: test that calling this function twice gets them from cache (or at least they're in cache after one call)
	if s == nil {
		err = fmt.Errorf(
			"%s - Session is required to retrieve cached/latest definitions",
			helpers.GetFunctionName())

		return
	}

	if len(s.FrontDoorsManagedRuleSetDefinitions) != 0 {
		logging.Debugf("returning cached rule set definitions")
		return s.FrontDoorsManagedRuleSetDefinitions, nil
	}

	if s.FrontDoorsManagedRuleSetsClients[subID] == nil {
		err = s.GetManagedRuleSetsClient(subID)
		if err != nil {
			return
		}
	}

	pager := s.FrontDoorsManagedRuleSetsClients[subID].NewListPager(nil)
	ctx := context.Background()

	for pager.More() {
		nextResult, merr := pager.NextPage(ctx)
		if merr != nil {
			return nil, fmt.Errorf("%s - %w", helpers.GetFunctionName(), merr)
		}

		rsds = append(rsds, nextResult.Value...)
	}

	return
}

// GetDeleteManagedRuleExclusionProcessScope returns the scope for deletion of Managed rule exclusions
// scopeFromSelectors works out which exclusion scope the three selectors name.
// The second return is false when they name none, which the callers turn into
// their own error.
//
// Both exported wrappers below ran this cascade themselves.
func scopeFromSelectors(ruleSetType, ruleGroup, ruleID string) (ExclusionScope, bool) {
	switch {
	case ruleID != "":
		// a rule id is the narrowest selector and wins outright
		return ScopeRule, true
	case ruleGroup != "":
		// a group, with or without a rule set, is group scope
		return ScopeRuleGroup, true
	case ruleSetType != "":
		return ScopeRuleSet, true
	default:
		return "", false
	}
}

// GetDeleteManagedRuleExclusionProcessScope returns the scope a deletion applies to.
func GetDeleteManagedRuleExclusionProcessScope(input *DeleteManagedRuleExclusionInput) (scope ExclusionScope, err error) {
	funcName := helpers.GetFunctionName()

	// RuleSetType is optional, and was previously dereferenced after the nil
	// check that guarded it, so a group-scoped delete with no rule set panicked
	ruleSetType := derefOrEmpty(input.RuleSetType)

	if ruleSetType == "" && input.RuleGroup == "" && input.RuleID == "" {
		return "", fmt.Errorf("%s - a rule id, rule group, or rule set was not provided", funcName)
	}

	if scope, ok := scopeFromSelectors(ruleSetType, input.RuleGroup, input.RuleID); ok {
		return scope, nil
	}

	return "", fmt.Errorf("%s - failed to determine scope based on input: RuleSet %s RuleGroup %s RuleId %s",
		funcName,
		valueOrDash(ruleSetType),
		valueOrDash(input.RuleGroup),
		valueOrDash(input.RuleID))
}

// GetAddManagedRuleExclusionProcessScope returns the scope an addition applies to.
func GetAddManagedRuleExclusionProcessScope(amrei AddManagedRuleExclusionInput) (scope ExclusionScope, err error) {
	funcName := helpers.GetFunctionName()

	// both pointers were dereferenced before anything checked them
	ruleSetType := derefOrEmpty(amrei.RuleSetType)
	ruleSetVersion := derefOrEmpty(amrei.RuleSetVersion)

	if ruleSetType == "" && ruleSetVersion == "" && amrei.RuleGroup == "" && amrei.RuleID == "" {
		return "", fmt.Errorf("%s - rule id, rule group, and rule set are required", funcName)
	}

	if scope, ok := scopeFromSelectors(ruleSetType, amrei.RuleGroup, amrei.RuleID); ok {
		return scope, nil
	}

	return "unhandled",
		fmt.Errorf("%s - failed to determine scope based on input: RuleSet %s_%s RuleGroup %s RuleId %s",
			funcName,
			valueOrDash(ruleSetType),
			valueOrDash(ruleSetVersion),
			valueOrDash(amrei.RuleGroup),
			valueOrDash(amrei.RuleID))
}

func IsValidExclusionRuleVariable(v armfrontdoor.ManagedRuleExclusionMatchVariable, ci bool) bool {
	if ci {
		for x := range ValidRuleExclusionMatchVariables {
			if strings.EqualFold(string(v), ValidRuleExclusionMatchVariables[x]) {
				return true
			}
		}

		return false
	}

	for x := range ValidRuleExclusionMatchVariables {
		if string(v) == ValidRuleExclusionMatchVariables[x] {
			return true
		}
	}

	return false
}

func NormaliseExclusionInput(inVar, inOp string) (outVar armfrontdoor.ManagedRuleExclusionMatchVariable, outOp armfrontdoor.ManagedRuleExclusionSelectorMatchOperator, err error) {
	var match bool

	match, outVar = NormaliseMatchVariable(inVar)
	if !match {
		err = fmt.Errorf("%s - please use one of: %s", helpers.GetFunctionName(), strings.Join(ValidRuleExclusionMatchVariables[:], ", "))

		return
	}

	match, outOp = NormaliseMatchOperator(inOp)
	if !match {
		err = fmt.Errorf("%s - please use one of: %s", helpers.GetFunctionName(), strings.Join(ValidRuleExclusionMatchOperators[:], ", "))
	}

	return
}

func NormaliseMatchVariable(mr string) (match bool, result armfrontdoor.ManagedRuleExclusionMatchVariable) {
	for _, matchVar := range ValidRuleExclusionMatchVariables {
		if strings.EqualFold(mr, matchVar) {
			return true, armfrontdoor.ManagedRuleExclusionMatchVariable(matchVar)
		}
	}

	return
}

func NormaliseMatchOperator(mo string) (match bool, result armfrontdoor.ManagedRuleExclusionSelectorMatchOperator) {
	for _, matchOp := range ValidRuleExclusionMatchOperators {
		if strings.EqualFold(mo, matchOp) {
			return true, armfrontdoor.ManagedRuleExclusionSelectorMatchOperator(matchOp)
		}
	}

	return
}

func getRuleSetStats(rs *armfrontdoor.ManagedRuleSet, rsd *armfrontdoor.ManagedRuleSetDefinition) (stats RuleSetStatsOutput) {
	if rs == nil {
		return stats
	}

	stats.RuleSetType = derefOrEmpty(rs.RuleSetType)
	stats.RuleSetVersion = derefOrEmpty(rs.RuleSetVersion)
	stats.RuleSetScopeExclusionsTotal = len(rs.Exclusions)

	mrsl := armfrontdoor.ManagedRuleSetList{
		ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{rs},
	}
	matchingDefinitionsOutput := getDefinitionMatchingExistingRuleSets(&getDefinitionsMatchingExistingRuleSetsInput{
		mrsdl:          []*armfrontdoor.ManagedRuleSetDefinition{rsd},
		mrsl:           &mrsl,
		ruleSetType:    stats.RuleSetType,
		ruleSetVersion: stats.RuleSetVersion,
	})

	if matchingDefinitionsOutput.RuleSetDefinition == nil ||
		matchingDefinitionsOutput.RuleSetDefinition.Properties == nil {
		return
	}

	// record the previous group name so we know when to output row with exclusions count
	for _, managedRuleSetDefinitionRuleGroup := range matchingDefinitionsOutput.RuleSetDefinition.Properties.RuleGroups {
		managedRuleSetDefinitionRuleGroup := managedRuleSetDefinitionRuleGroup
		rgExclusions := getRuleGroupExclusions(derefOrEmpty(managedRuleSetDefinitionRuleGroup.RuleGroupName),
			[]*armfrontdoor.ManagedRuleSet{rs})
		stats.RuleGroupScopeExclusionsTotal += len(rgExclusions)
		stats.GroupCount++
		// loop through each rule in group, making those we have overrided and have exclusions for
		for _, rg := range managedRuleSetDefinitionRuleGroup.Rules {
			rg := rg
			// check if rule has any overrides configured
			stats.Rules++

			exclusions, ruleAction, ruleEnabledState := getRuleConfig(*managedRuleSetDefinitionRuleGroup.RuleGroupName, rg, *rs)
			stats.RuleScopeExclusionsTotal += len(exclusions)

			switch ruleEnabledState {
			case "":
				if *rg.DefaultState == armfrontdoor.ManagedRuleEnabledStateEnabled {
					stats.RulesEnabled++
				}
			case "Enabled":
				stats.RulesEnabled++
				if *rg.DefaultState == armfrontdoor.ManagedRuleEnabledStateDisabled {
					stats.RulesDefaultEnabledStateOveridden++
				}
			default:
				// must be disabled
				if *rg.DefaultState == armfrontdoor.ManagedRuleEnabledStateEnabled {
					stats.RulesDefaultEnabledStateOveridden++
				}
			}

			if ruleAction != nil && *ruleAction != *rg.DefaultAction {
				stats.RulesDefaultActionOveridden++
			}

			switch *ruleAction {
			case armfrontdoor.ActionTypeBlock:
				stats.BlockTotal++
			case armfrontdoor.ActionTypeLog:
				stats.LogTotal++
			case armfrontdoor.ActionTypeAllow:
				stats.AllowTotal++
			case armfrontdoor.ActionTypeRedirect:
				stats.RedirectTotal++
			default:
				// if unset, get default
				switch *rg.DefaultAction {
				case armfrontdoor.ActionTypeBlock:
					stats.BlockTotal++
				case armfrontdoor.ActionTypeLog:
					stats.LogTotal++
				case armfrontdoor.ActionTypeAllow:
					stats.AllowTotal++
				case armfrontdoor.ActionTypeRedirect:
					stats.RedirectTotal++
				}
			}
		}

		stats.RulesDisabled = stats.Rules - stats.RulesEnabled
	}

	stats.TotalExclusions = stats.RuleSetScopeExclusionsTotal +
		stats.RuleGroupScopeExclusionsTotal +
		stats.RuleScopeExclusionsTotal

	return
}
