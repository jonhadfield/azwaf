package policy

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"go4.org/netipx"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"
	"github.com/jonhadfield/azwaf/session"
)

type filterCustomRulesInput struct {
	names       []string
	namePrefix  RuleNamePrefix
	customRules []*armfrontdoor.CustomRule
	action      *armfrontdoor.ActionType
	ruleType    *armfrontdoor.RuleType
}

func customRuleNamePrefixCheck(in filterCustomRulesInput, cr *armfrontdoor.CustomRule) bool {
	if in.namePrefix == "" {
		return false
	}

	if (in.action != nil && *in.action != *cr.Action) ||
		(in.ruleType != nil && *in.ruleType != *cr.RuleType) ||
		(in.namePrefix != "" && !strings.HasPrefix(*cr.Name, string(in.namePrefix))) {

		return false
	}

	return true
}

func customRuleNamesCheck(in filterCustomRulesInput, cr *armfrontdoor.CustomRule) bool {
	if len(in.names) == 0 || cr == nil {
		return false
	}

	for _, name := range in.names {
		if (in.action != nil && *in.action != *cr.Action) ||
			(in.ruleType != nil && *in.ruleType != *cr.RuleType) ||
			(*cr.Name != name) {

			continue
		}

		return true
	}

	return false
}

func filterCustomRules(in filterCustomRulesInput) ([]*armfrontdoor.CustomRule, error) {
	if in.customRules == nil {
		return nil, fmt.Errorf("filtering custom rules requires a list of custom rules")
	}

	if in.ruleType == nil {
		return nil, errors.New("filtering custom rules requires a type is set")
	}

	if in.action == nil {
		return nil, errors.New("filtering custom rules requires an action is set")
	}

	var filtered []*armfrontdoor.CustomRule

	for _, cr := range in.customRules {
		cr := cr

		if customRuleNamesCheck(in, cr) {
			filtered = append(filtered, cr)

			// only one name can match
			return filtered, nil
		}

		if customRuleNamePrefixCheck(in, cr) {
			filtered = append(filtered, cr)
		}
	}

	return filtered, nil
}

// ipNetsFromRule splits a rule's IP match conditions into the prefixes it
// matches on and the prefixes it negates.
//
// Callers disagree about what a non-IP match condition means. Generating rules
// from scratch, a mixed rule (IPMatch + GeoMatch) cannot be represented, so it
// is an error. Reading an existing rule to add to it, the non-IP conditions are
// carried over untouched by getNonIPMatchConditions, so they are skipped here.
func ipNetsFromRule(cr *armfrontdoor.CustomRule, skipUnsupported bool) ([]netip.Prefix, []netip.Prefix, error) {
	var positive, negative []netip.Prefix

	if cr == nil {
		return nil, nil, nil
	}

	for _, mc := range cr.MatchConditions {
		if mc == nil {
			continue
		}

		// rules with mixed match conditions are not currently supported
		if !matchConditionSupported(mc) {
			if skipUnsupported {
				continue
			}

			return nil, nil, fmt.Errorf("rule %s has match condition that does not match constraints", derefOrEmpty(cr.Name))
		}

		// an absent negate flag means the condition is not negated
		negated := mc.NegateCondition != nil && *mc.NegateCondition

		for _, mv := range mc.MatchValue {
			n, err := tryNetStrToPrefix(derefOrEmpty(mv))
			if err != nil {
				return nil, nil, err
			}

			if negated {
				negative = append(negative, n)
			} else {
				positive = append(positive, n)
			}
		}
	}

	return positive, negative, nil
}

func getIPNetsForPrefix(customRules []*armfrontdoor.CustomRule, action *armfrontdoor.ActionType) ([]netip.Prefix, []netip.Prefix, error) {
	var positive, negative []netip.Prefix

	if action == nil {
		return nil, nil, errors.New("action cannot be nil")
	}

	for _, cr := range customRules {
		pos, neg, err := ipNetsFromRule(cr, false)
		if err != nil {
			return nil, nil, err
		}

		positive = append(positive, pos...)
		negative = append(negative, neg...)
	}

	return positive, negative, nil
}

func getIPNetsForRuleIPMatchConditions(cr *armfrontdoor.CustomRule) ([]netip.Prefix, []netip.Prefix, error) {
	return ipNetsFromRule(cr, true)
}

func getNonIPMatchConditions(cr *armfrontdoor.CustomRule) []*armfrontdoor.MatchCondition {
	var result []*armfrontdoor.MatchCondition

	mc := cr.MatchConditions

	// for each match conditions, get the
	for y := range mc {
		// ensure match condition is IP as rules with mixed match
		// conditions (IPMatch + GeoMatch combination)
		//  are not currently supported
		if *mc[y].Operator == armfrontdoor.OperatorIPMatch {
			continue
		}

		result = append(result, mc[y])
	}

	return result
}

type DecorateExistingCustomRuleInput struct {
	BaseCLIInput
	Policy                  *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID          string
	RawResourceID           string
	ResourceID              config.ResourceID
	Action                  *armfrontdoor.ActionType
	Filepath                string
	AdditionalAddrs         IPNets
	AdditionalExcludedAddrs IPNets
	RuleName                string
	RuleType                *armfrontdoor.RuleType
	// RateLimitDurationInMinutes *int32
	// RateLimitThreshold         *int32
	PriorityStart int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *slog.Level
}

type UpdatePolicyCustomRulesIPMatchPrefixesInput struct {
	BaseCLIInput
	Policy                     *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID             string
	RawResourceID              string
	ResourceID                 config.ResourceID
	Action                     *armfrontdoor.ActionType
	Filepath                   string
	Addrs                      IPNets
	ReplaceAddrs               bool
	ExcludedAddrs              IPNets
	RuleNamePrefix             RuleNamePrefix
	RuleType                   *armfrontdoor.RuleType
	RateLimitDurationInMinutes *int32
	RateLimitThreshold         *int32
	PriorityStart              int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *slog.Level
}

func loadLocalPrefixes(filepath string, prefixes IPNets) (IPNets, error) {
	var res IPNets

	var err error

	if filepath != "" {
		res, err = loadIPsFromPath(filepath)
		if err != nil {
			return nil, fmt.Errorf("failed to load IPs from path: %s", err)
		}
	}

	res = append(res, prefixes...)

	if len(res) == 0 {
		return prefixes, errors.New("no local prefixes loaded")
	}

	return res, nil
}

// getGroupByFromRules returns the GroupBy clause from the first rule if one
// exists.  It returns an empty slice if there are no rules.
func getGroupByFromRules(rules []*armfrontdoor.CustomRule) []*armfrontdoor.GroupByVariable {
	if len(rules) == 0 {
		return []*armfrontdoor.GroupByVariable{}
	}

	return rules[0].GroupBy
}

// mergePrefixesWithExisting appends the IP prefixes extracted from existing
// rules to the provided positive and negative prefix slices.  The resulting
// slices are normalised before being returned.
func mergePrefixesWithExisting(rules []*armfrontdoor.CustomRule, action *armfrontdoor.ActionType, pos, neg IPNets) (IPNets, IPNets, error) {
	existingPos, existingNeg, err := getIPNetsForPrefix(rules, action)
	if err != nil {
		return nil, nil, err
	}

	pos = append(pos, existingPos...)
	pos, err = Normalise(pos)
	if err != nil {
		return nil, nil, err
	}

	neg = append(neg, existingNeg...)
	neg, err = Normalise(neg)
	if err != nil {
		return nil, nil, err
	}

	return pos, neg, nil
}

// replaceRulesWithPrefix removes any existing custom rules whose name has the
// supplied prefix and appends the provided rules.
func replaceRulesWithPrefix(p *armfrontdoor.WebApplicationFirewallPolicy, prefix RuleNamePrefix, newRules []*armfrontdoor.CustomRule) {
	var cleaned []*armfrontdoor.CustomRule

	for _, r := range policyCustomRules(p) {
		if !strings.HasPrefix(*r.Name, string(prefix)) {
			cleaned = append(cleaned, r)
		}
	}

	p.Properties.CustomRules.Rules = append(cleaned, newRules...)
}

type RuleNamePrefix string

var (
	ruleNamePrefixTestStartNumber = regexp.MustCompile(`^[0-9].*`)
	ruleNamePrefixTestEndNumber   = regexp.MustCompile(`^[a-zA-Z]+[0-9]+$`)
)

func (r RuleNamePrefix) Check() error {
	rs := string(r)

	switch {
	case len(rs) == 0:
		return errors.New("rule name prefix cannot be empty")
	case ruleNamePrefixTestStartNumber.MatchString(rs):
		return errors.New("rule name prefix cannot start with a number")
	case ruleNamePrefixTestEndNumber.MatchString(rs):
		return errors.New("rule name prefix cannot end with a number")
	case strings.Contains(rs, " "):
		return errors.New("rule name prefix cannot contain white space")
	default:
		return nil
	}
}

func ValidateUpdatePolicyInput(in UpdatePolicyCustomRulesIPMatchPrefixesInput) error {
	funcName := helpers.GetFunctionName()

	if len(in.Addrs) == 0 && len(in.ExcludedAddrs) == 0 {
		return fmt.Errorf("no networks provided")
	}

	if in.Policy == nil {
		return fmt.Errorf("%s - policy is nil", funcName)
	}

	if in.Action == nil {
		return fmt.Errorf("%s - action is nil", funcName)
	}

	if slices.Contains(armfrontdoor.PossibleActionTypeValues(), *in.Action) {
		if err := in.RuleNamePrefix.Check(); err != nil {
			return err
		}
	}

	if in.Policy == nil {
		return fmt.Errorf("missing policy")
	}

	if in.Policy.Properties == nil {
		return fmt.Errorf("policy missing properties")
	}

	return nil
}

// UpdatePolicyCustomRulesIPMatchPrefixes updates an existing Custom Policy with prefixes matching the requested action
func UpdatePolicyCustomRulesIPMatchPrefixes(in UpdatePolicyCustomRulesIPMatchPrefixesInput) (bool, GeneratePolicyPatchOutput, error) {
	if err := ValidateUpdatePolicyInput(in); err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	if in.LogLevel != nil {
		logging.SetLevel(*in.LogLevel)
	}

	// take a copy of the Policy for later comparison
	originalPolicy, err := CopyPolicy(*in.Policy)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	positivePrefixes, err := loadLocalPrefixes(in.Filepath, in.Addrs)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	negativePrefixes := in.ExcludedAddrs

	filtered, err := filterCustomRules(filterCustomRulesInput{
		namePrefix:  in.RuleNamePrefix,
		customRules: policyCustomRules(in.Policy),
		action:      in.Action,
		ruleType:    in.RuleType,
	})
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	// get groupby clause from filtered to ensure we generate new custom rules with the same
	gbv := getGroupByFromRules(filtered)

	// if we're not replacing the existing rules, then append the existing rules to the new rules
	if !in.ReplaceAddrs {
		positivePrefixes, negativePrefixes, err = mergePrefixesWithExisting(filtered, in.Action, positivePrefixes, negativePrefixes)
		if err != nil {
			return false, GeneratePolicyPatchOutput{}, err
		}
	}

	crs, err := GenCustomRulesFromIPNets(GenCustomRulesFromIPNetsInput{
		PositiveMatchNets:          positivePrefixes,
		NegativeMatchNets:          negativePrefixes,
		GroupBy:                    gbv,
		RuleType:                   in.RuleType,
		RateLimitDurationInMinutes: in.RateLimitDurationInMinutes,
		RateLimitThreshold:         in.RateLimitThreshold,
		Action:                     in.Action,
		MaxRules:                   in.MaxRules,
		CustomNamePrefix:           in.RuleNamePrefix,
		CustomPriorityStart:        in.PriorityStart,
	})
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	// remove existing rules with the prefix and append the new ones
	replaceRulesWithPrefix(in.Policy, in.RuleNamePrefix, crs)
	// o, _ := json.MarshalIndent(in.Policy.Properties.CustomRules.Rules, "", "  ")

	if len(policyCustomRules(in.Policy)) > MaxCustomRules {
		return false, GeneratePolicyPatchOutput{}, fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	}

	// sort rules by priority
	sortCustomRulesByPriority(policyCustomRules(in.Policy))
	sortCustomRulesByPriority(policyCustomRules(&originalPolicy))

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: originalPolicy, New: *in.Policy})
	if err != nil {
		return false, patch, err
	}

	if patch.TotalDifferences == 0 {
		logging.Debug("nothing to do")

		return false, patch, nil
	}

	if patch.ManagedRuleChanges != 0 {
		return true, patch, fmt.Errorf("unexpected Managed rules changes. aborting")
	}

	return true, patch, nil
}

func getRateLimitConfig(rules []*armfrontdoor.CustomRule) (*int32, *int32, error) {
	var lastDuration *int32

	var lastThreshold *int32

	// ensure all rules have the same rate limit configuration
	for x, cr := range rules {
		cr := cr

		ruleName := "not defined"
		if cr.Name != nil {
			ruleName = *cr.Name
		}

		if cr.RuleType == nil {
			return nil, nil, fmt.Errorf("rule %d - %s has no rule type", x, ruleName)
		}

		switch *cr.RuleType {
		case armfrontdoor.RuleTypeRateLimitRule:
			if cr.RateLimitDurationInMinutes == nil {
				return nil, nil, fmt.Errorf("rate limit rule %s has no rate limit duration", ruleName)
			}

			if cr.RateLimitThreshold == nil {
				return nil, nil, fmt.Errorf("rate limit rule %s has no rate limit threshold", ruleName)
			}
		case armfrontdoor.RuleTypeMatchRule:
			if cr.RateLimitDurationInMinutes != nil || cr.RateLimitThreshold != nil {
				return nil, nil, fmt.Errorf("match rule %s has rate limit configuration", ruleName)
			}
		default:
			return nil, nil, fmt.Errorf("rule %s has unknown rule type", ruleName)
		}

		// grab the first rule's rate limit configuration
		if x == 0 {
			// if the first rule has a rate limit configuration, then set the lastDuration and lastThreshold
			if cr.RateLimitDurationInMinutes != nil && cr.RateLimitThreshold != nil {
				lastDuration = cr.RateLimitDurationInMinutes
				lastThreshold = cr.RateLimitThreshold

				continue
			}
		}

		// check each rule has the same non-existant/existant rate limit configuration
		if cr.RateLimitDurationInMinutes != nil && cr.RateLimitThreshold != nil {
			if (lastThreshold != nil && *lastThreshold != *cr.RateLimitThreshold) || (lastDuration != nil && *lastDuration != *cr.RateLimitDurationInMinutes) {
				return nil, nil, fmt.Errorf("rules have different rate limit configurations")
			}
		}
	}

	return lastThreshold, lastDuration, nil
}

func ValidateDecorateExistingCustomRuleInput(in DecorateExistingCustomRuleInput) error {
	funcName := helpers.GetFunctionName()

	if len(in.AdditionalAddrs) == 0 && len(in.AdditionalExcludedAddrs) == 0 {
		return fmt.Errorf("no networks provided")
	}

	if in.Policy == nil {
		return fmt.Errorf("%s - policy is nil", funcName)
	}

	if policyCustomRuleList(in.Policy) == nil {
		return fmt.Errorf("%s - policy has no custom rules section", funcName)
	}

	if policyCustomRules(in.Policy) == nil {
		return fmt.Errorf("%s - policy has no custom rules", funcName)
	}

	// the nil-Properties check that used to sit here ran *after* the line above
	// had already dereferenced Properties, so it could never fire. The accessor
	// covers that case now, returning nil and erroring above.

	if in.RuleName == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if in.RuleType == nil {
		return fmt.Errorf("rule type cannot be nil")
	}

	return nil
}

// rebuild the IP match conditions for the "IP Address" match type
func rebuildIPMatchConditions(ruleToDecorate *armfrontdoor.CustomRule, additionalPositivePrefixes, additionalNegativePrefixes []netip.Prefix) ([]*armfrontdoor.MatchCondition, []*armfrontdoor.MatchCondition, error) {
	var posMatchConditions, negMatchConditions []*armfrontdoor.MatchCondition

	existingPositiveAddrs, existingNegativeAddrs, err := getIPNetsForRuleIPMatchConditions(ruleToDecorate)
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	// get a copy of the existing ipnets for the specified action and append to the list of new nets
	additionalPositivePrefixes = append(additionalPositivePrefixes, existingPositiveAddrs...)

	// appending existingAddrs to new set may result in overlap so normalise
	additionalPositivePrefixes, err = Normalise(additionalPositivePrefixes)
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	additionalNegativePrefixes = append(additionalNegativePrefixes, existingNegativeAddrs...)
	// appending existingAddrs to new set may result in overlap so normalise
	additionalNegativePrefixes, err = Normalise(additionalNegativePrefixes)
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	return matchConditionsFromNets(additionalPositivePrefixes, additionalNegativePrefixes)
}

// matchConditionsFromNets turns two sets of prefixes into the match conditions
// carrying them, chunked to stay inside Azure's per-rule value limit.
//
// Every rule repeats the whole negated set, so the negated set is what is left
// over for the positive one; past 599 there is no room for a positive value and
// the chunking would silently emit one oversized condition.
func matchConditionsFromNets(positive, negative []netip.Prefix) ([]*armfrontdoor.MatchCondition, []*armfrontdoor.MatchCondition, error) {
	deDupedNegatedNets := deDupeIPNets(negative)
	sort.Strings(deDupedNegatedNets)
	logging.Tracef("total negated networks after deduplication: %d", len(deDupedNegatedNets))

	deDupedNets := deDupeIPNets(positive)
	sort.Strings(deDupedNets)
	logging.Tracef("total networks after deduplication: %d", len(deDupedNets))

	if len(deDupedNegatedNets) >= MaxIPMatchValues-1 {
		return nil, nil, fmt.Errorf("%d negated match values specified but cannot exceed %d", len(deDupedNegatedNets), MaxIPMatchValues-1)
	}

	positiveMatchConditions, err := generateMatchConditionsFromNets(generateMatchConditionsFromNetsInput{
		nets:                  &deDupedNets,
		negate:                false,
		maxValuesPerCondition: MaxIPMatchValues - len(deDupedNegatedNets),
		// TODO: should respect the existing match variable
		matchVariable: toPtr(armfrontdoor.MatchVariableSocketAddr),
		matchOperator: toPtr(armfrontdoor.OperatorIPMatch),
	})
	if err != nil {
		return nil, nil, err
	}

	logging.Tracef("positive match conditions: %d", len(positiveMatchConditions))

	negativeMatchConditions, err := generateMatchConditionsFromNets(generateMatchConditionsFromNetsInput{
		nets:   &deDupedNegatedNets,
		negate: true,
		// TODO: set to Max (600) minus the largest possible chunk of positive
		maxValuesPerCondition: MaxIPMatchValues,
		matchVariable:         toPtr(armfrontdoor.MatchVariableSocketAddr),
		matchOperator:         toPtr(armfrontdoor.OperatorIPMatch),
	})
	if err != nil {
		return nil, nil, err
	}

	logging.Tracef("negative match conditions: %d", len(negativeMatchConditions))

	return positiveMatchConditions, negativeMatchConditions, nil
}

// DecorateExistingCustomRule adds to an existing Custom Policy with prefixes matching the requested action
func DecorateExistingCustomRule(in DecorateExistingCustomRuleInput) (bool, GeneratePolicyPatchOutput, error) {
	if err := ValidateDecorateExistingCustomRuleInput(in); err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	if in.LogLevel != nil {
		logging.SetLevel(*in.LogLevel)
	}

	// take a copy of the Policy for later comparison
	originalPolicy, err := CopyPolicy(*in.Policy)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	// positivePrefixes are those to match without negation
	var positivePrefixes []netip.Prefix
	if in.Filepath != "" || len(in.AdditionalAddrs) > 0 {
		positivePrefixes, err = loadLocalPrefixes(in.Filepath, in.AdditionalAddrs)
		if err != nil {
			return false, GeneratePolicyPatchOutput{}, err
		}
	}

	// retrieve specified rule by name
	filtered, err := filterCustomRules(filterCustomRulesInput{
		names:       []string{in.RuleName},
		customRules: policyCustomRules(in.Policy),
		ruleType:    in.RuleType,
		action:      in.Action,
	})
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	if len(filtered) == 0 {
		if in.Policy.Name != nil {
			return false, GeneratePolicyPatchOutput{}, fmt.Errorf("no custom rule found with name %s, type %s, action %s in policy %s", in.RuleName, *in.RuleType, *in.Action, *in.Policy.Name)
		}

		return false, GeneratePolicyPatchOutput{}, fmt.Errorf("no custom rule found with name %s, type %s, and action %s", in.RuleName, *in.RuleType, *in.Action)
	}

	ruleToDecorate := filtered[0]

	// start creating a replacement list of match conditions by starting
	// with the existing non-IP match conditions
	replacementMatchConditions := getNonIPMatchConditions(ruleToDecorate)

	positiveMatchConditions, negativeMatchConditions, err := rebuildIPMatchConditions(ruleToDecorate, positivePrefixes, in.AdditionalExcludedAddrs)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	replacementMatchConditions = append(replacementMatchConditions, positiveMatchConditions...)
	replacementMatchConditions = append(replacementMatchConditions, negativeMatchConditions...)

	// replace match conditions
	ruleToDecorate.MatchConditions = replacementMatchConditions

	sortCustomRulesByPriority(policyCustomRules(in.Policy))
	sortCustomRulesByPriority(policyCustomRules(&originalPolicy))

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: originalPolicy, New: *in.Policy})
	if err != nil {
		return false, patch, err
	}

	// op, _ := json.MarshalIndent(originalPolicy, "", "  ")
	// os.WriteFile("orig", op, 0644)

	// np, _ := json.MarshalIndent(*in.Policy, "", "  ")
	// os.WriteFile("new", np, 0644)

	if patch.TotalDifferences == 0 {
		logging.Debug("nothing to do")

		return false, patch, nil
	}

	if patch.ManagedRuleChanges != 0 {
		return true, patch, fmt.Errorf("unexpected Managed rules changes. aborting")
	}

	return true, patch, nil
}

// sortCustomRulesByPriority orders rules ascending by priority, in place. A
// rule with no priority sorts first rather than panicking the comparator.
func sortCustomRulesByPriority(in []*armfrontdoor.CustomRule) {
	priority := func(r *armfrontdoor.CustomRule) int32 {
		if r == nil || r.Priority == nil {
			return 0
		}

		return *r.Priority
	}

	sort.Slice(in, func(i, j int) bool {
		return priority(in[i]) < priority(in[j])
	})
}

type IPNets []netip.Prefix

// toString receives slice of net.IPNet and returns a slice of their string representations
func (i *IPNets) toString() []string {
	var res []string

	for x := range *i {
		ipn := (*i)[x]
		res = append(res, ipn.String())
	}

	return res
}

// deDupeIPNets accepts a slice of net.IPNet and returns a unique slice of their string representations
func deDupeIPNets(ipns IPNets) []string {
	var res []string

	// check overlaps
	seen := make(map[string]bool)

	for _, i := range ipns.toString() {
		if _, ok := seen[i]; ok {
			continue
		}

		res = append(res, i)
		seen[i] = true
	}

	return res
}

// Normalise accepts a slice of netip.Prefix and returns a unique slice of their string representations
func Normalise(iPrefixes []netip.Prefix) ([]netip.Prefix, error) {
	ipsetBuilder := netipx.IPSetBuilder{}

	for x := range iPrefixes {
		if !iPrefixes[x].IsValid() {
			logging.Errorf("invalid prefix: %s\n", iPrefixes[x].String())

			continue
		}

		ipsetBuilder.AddPrefix(iPrefixes[x])
	}

	ipSet, err := ipsetBuilder.IPSet()
	if err != nil {
		return nil, err
	}

	logging.Tracef("normalised %d to %d prefixes", len(iPrefixes), len(ipSet.Prefixes()))

	return ipSet.Prefixes(), nil
}

type GenCustomRulesFromIPNetsInput struct {
	PositiveMatchNets          IPNets
	NegativeMatchNets          IPNets
	GroupBy                    []*armfrontdoor.GroupByVariable
	RuleType                   *armfrontdoor.RuleType
	RateLimitDurationInMinutes *int32
	RateLimitThreshold         *int32
	Action                     *armfrontdoor.ActionType
	MaxRules                   int
	CustomNamePrefix           RuleNamePrefix
	CustomPriorityStart        int
}

// validateGenCustomRulesInput ensures required fields are set and valid
func validateGenCustomRulesInput(in GenCustomRulesFromIPNetsInput) error {
	if in.Action == nil {
		return fmt.Errorf("action cannot be nil")
	}

	if !slices.Contains(armfrontdoor.PossibleActionTypeValues(), *in.Action) {
		return fmt.Errorf("invalid action: %s", *in.Action)
	}

	if in.RuleType == nil {
		return fmt.Errorf("rule type cannot be nil")
	}

	if !slices.Contains(armfrontdoor.PossibleRuleTypeValues(), *in.RuleType) {
		return fmt.Errorf("invalid rule type: %s %w", *in.RuleType, ErrInvalidRuleType)
	}

	return nil
}

// prepareMatchConditions converts provided prefixes into match conditions for rule generation
func prepareMatchConditions(in GenCustomRulesFromIPNetsInput) ([]*armfrontdoor.MatchCondition, []*armfrontdoor.MatchCondition, error) {
	return matchConditionsFromNets(in.PositiveMatchNets, in.NegativeMatchNets)
}

// buildCustomRules iterates over match conditions and creates the resulting custom rules
func buildCustomRules(pos, neg []*armfrontdoor.MatchCondition, in GenCustomRulesFromIPNetsInput, start int32) []*armfrontdoor.CustomRule {
	var crs []*armfrontdoor.CustomRule

	priorityCount := start

	for x := range pos {
		mcs := []*armfrontdoor.MatchCondition{pos[x]}
		if len(neg) == 1 {
			mcs = append(mcs, neg[0])
		}

		cr := genCustomRuleFromMatchConditions(genCustomRuleFromMatchConditionsInput{
			mcs:                        mcs,
			priority:                   priorityCount,
			action:                     in.Action,
			groupBy:                    in.GroupBy,
			namePrefix:                 string(in.CustomNamePrefix),
			ruleType:                   in.RuleType,
			rateLimitDurationInMinutes: in.RateLimitDurationInMinutes,
			rateLimitThreshold:         in.RateLimitThreshold,
		})

		logging.Tracef("generated match condition: %d", priorityCount+1)

		crs = append(crs, &cr)

		priorityCount++

		if len(crs) == in.MaxRules {
			break
		}
	}

	return crs
}

// GenCustomRulesFromIPNets accepts two lists of IPs (positive and negative), plus the action to be taken with them, and the maximum
// number of rules to create and then returns a slice of CustomRules
func GenCustomRulesFromIPNets(in GenCustomRulesFromIPNetsInput) ([]*armfrontdoor.CustomRule, error) {
	if err := validateGenCustomRulesInput(in); err != nil {
		return nil, err
	}

	priorityStart := int32(in.CustomPriorityStart)

	pos, neg, err := prepareMatchConditions(in)
	if err != nil {
		return nil, err
	}

	crs := buildCustomRules(pos, neg, in, priorityStart)

	sort.Slice(crs, func(i, j int) bool {
		return *crs[i].Priority < *crs[j].Priority
	})

	return crs, nil
}

type genCustomRuleFromMatchConditionsInput struct {
	mcs                        []*armfrontdoor.MatchCondition
	priority                   int32
	action                     *armfrontdoor.ActionType
	groupBy                    []*armfrontdoor.GroupByVariable
	namePrefix                 string
	ruleType                   *armfrontdoor.RuleType
	rateLimitDurationInMinutes *int32
	rateLimitThreshold         *int32
}

func genCustomRuleFromMatchConditions(in genCustomRuleFromMatchConditionsInput) armfrontdoor.CustomRule {
	name := fmt.Sprintf("%s%d", in.namePrefix, in.priority)

	return armfrontdoor.CustomRule{
		Action:                     in.action,
		MatchConditions:            in.mcs,
		Priority:                   &in.priority,
		RuleType:                   in.ruleType,
		GroupBy:                    in.groupBy,
		EnabledState:               toPtr(armfrontdoor.CustomRuleEnabledStateEnabled),
		Name:                       &name,
		RateLimitDurationInMinutes: in.rateLimitDurationInMinutes,
		RateLimitThreshold:         in.rateLimitThreshold,
	}
}

type generateMatchConditionsFromNetsInput struct {
	nets                  *[]string
	negate                bool
	maxValuesPerCondition int
	matchVariable         *armfrontdoor.MatchVariable
	matchOperator         *armfrontdoor.Operator
}

func generateMatchConditionsFromNets(in generateMatchConditionsFromNetsInput) (mcs []*armfrontdoor.MatchCondition, err error) {
	var chunk []*string

	for x, net := range *in.nets {
		net := net
		chunk = append(chunk, &net)

		// if we've reached the end, or max chunk size then add match
		// condition and reset chunk
		if x+1 == len(*in.nets) || len(chunk) == in.maxValuesPerCondition {
			var mc armfrontdoor.MatchCondition

			sort.Slice(chunk, func(i, j int) bool {
				return netipx.ComparePrefix(netip.MustParsePrefix(*chunk[i]), netip.MustParsePrefix(*chunk[j])) < 0
			})

			mc.MatchValue = chunk
			mc.NegateCondition = toPtr(in.negate)
			mc.Operator = in.matchOperator
			mc.MatchVariable = toPtr(armfrontdoor.MatchVariableSocketAddr)
			mc.Transforms = []*armfrontdoor.TransformType{}

			mcs = append(mcs, &mc)

			// reset chunk
			chunk = []*string{}
		}
	}

	return
}

// readIPsFromFile accepts a file path from which to load IPs (one per line) as strings and return a slice of
func readIPsFromFile(fPath string) (IPNets, error) {
	var ipnets IPNets

	// #nosec
	file, err := os.Open(fPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", fPath, err)
	}

	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var ipnet netip.Prefix

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			if !strings.Contains(line, "/") {
				line += "/32"
			}

			ipnet, err = netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("failed to parse prefix: %s", err)
			}

			ipnets = append(ipnets, ipnet)
		}
	}

	return ipnets, nil
}

// loadIPsFromPath accepts a file path or directory and then generates a fully qualified path
// in order to call a function to load the ips from each fully qualified file path
func loadIPsFromPath(path string) (IPNets, error) {
	var ipNets IPNets

	// if path is a folder, then loop through contents
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("path %s does not exist", path)
	}

	if info.IsDir() {
		var files []os.DirEntry

		files, err = os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %s", err)
		}

		if len(files) == 0 {
			return nil, fmt.Errorf("no files found in %s", path)
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			var n IPNets

			p := filepath.Join(path, file.Name())

			n, err = readIPsFromFile(p)
			if err != nil {
				return nil, fmt.Errorf("failed to load ips from file: %s", err)
			}

			logging.Infof("loaded %d ips from file %s", len(n), p)

			ipNets = append(ipNets, n...)
		}

		return ipNets, nil
	}

	var n IPNets

	n, err = readIPsFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load ips from file: %s", err)
	}

	logging.Debugf("loaded %d ips from file %s", len(n), path)

	ipNets = append(ipNets, n...)

	return ipNets, nil
}

type AddCustomRulesPrefixesInput struct {
	BaseCLIInput
	Session        *session.Session
	Policy         *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID string
	RawResourceID  string
	ResourceID     config.ResourceID
	Action         armfrontdoor.ActionType
	DryRun         bool
	Filepath       string
	Addrs          IPNets
	RuleNamePrefix RuleNamePrefix
	PriorityStart  int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *slog.Level
}

// matchConditionSupported returns true if is for IPMatch
// and is for remote address or socket addresses
func matchConditionSupported(mc *armfrontdoor.MatchCondition) bool {
	if mc.MatchVariable == nil || mc.Operator == nil {
		logging.Warnf("match condition missing variable or operator")

		return false
	}

	// removing a prefix is only valid for remote or socket address
	if !slices.Contains([]armfrontdoor.MatchVariable{armfrontdoor.MatchVariableRemoteAddr, armfrontdoor.MatchVariableSocketAddr}, *mc.MatchVariable) {
		logging.Warnf("match condition is not remote address nor socket address so not valid for unblock")
		return false
	}

	if *mc.Operator != armfrontdoor.OperatorIPMatch {
		logging.Warnf("match condition operator not ip match so not valid for unblock")
		return false
	}

	return true
}

func tryNetStrToPrefix(inNetStr string) (netip.Prefix, error) {
	// if no mask then try parsing as address
	if !strings.Contains(inNetStr, "/") {
		addr, err := netip.ParseAddr(inNetStr)
		if err != nil {
			return netip.Prefix{}, err
		}

		return addr.Prefix(addr.BitLen())
	}

	return netip.ParsePrefix(inNetStr)
}
