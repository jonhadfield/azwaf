package policy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func getIPNetsForPrefix(policy *armfrontdoor.WebApplicationFirewallPolicy, prefix RuleNamePrefix, action *armfrontdoor.ActionType) (nets []netip.Prefix, err error) {
	if policy.Properties.CustomRules == nil {
		return nil, nil
	}

	if action == nil {
		return nil, errors.New("action cannot be nil")
	}

	for x := range policy.Properties.CustomRules.Rules {
		// ensure action is matching
		if *policy.Properties.CustomRules.Rules[x].Action != *action {
			continue
		}

		// if prefix is empty, then all custom rules are interrogated
		if strings.HasPrefix(*policy.Properties.CustomRules.Rules[x].Name, string(prefix)) {
			mc := policy.Properties.CustomRules.Rules[x].MatchConditions

			for y := range mc {
				// ensure match condition is IP
				if !matchConditionValidForUnblock(mc[y]) {
					return nil, fmt.Errorf("rule %s has match condition that does not match constraints", *policy.Properties.CustomRules.Rules[x].Name)
				}

				for z := range mc[y].MatchValue {
					n, tErr := tryNetStrToPrefix(*mc[y].MatchValue[z])
					if tErr != nil {
						return nets, tErr
					}

					if err != nil {
						return nil, fmt.Errorf("rule %s has entry with invalid net %s", *policy.Properties.CustomRules.Rules[x].Name, *mc[y].MatchValue[z])
					}

					nets = append(nets, n)
				}
			}
		}
	}

	return
}

type RemoveNetsInput struct {
	BaseCLIInput
	Session       *session.Session
	RawResourceID string
	MatchPrefix   RuleNamePrefix
	ResourceID    config.ResourceID
	Action        armfrontdoor.ActionType
	Filepath      string
	Nets          []netip.Prefix
	MaxRules      int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

type ApplyRemoveNetsInput struct {
	BaseCLIInput
	RID         config.ResourceID
	MatchPrefix RuleNamePrefix
	Action      armfrontdoor.ActionType
	Output      bool
	DryRun      bool
	Filepath    string
	Addrs       IPNets
	MaxRules    int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

// RemoveNets removes selected networks from custom rules
func RemoveNets(input *RemoveNetsInput) (results []ApplyRemoveNetsResult, err error) {
	if input.LogLevel != nil {
		logrus.SetLevel(*input.LogLevel)
	}

	if input.Session == nil {
		input.Session = session.New()
	}

	policyID := input.ResourceID

	if policyID.Raw == "" {
		if IsRIDHash(input.RawResourceID) {
			policyID, err = GetPolicyResourceIDByHash(input.Session, input.SubscriptionID, input.RawResourceID)

			if err != nil {
				return results, err
			}
		}
	}

	results, err = ApplyRemoveAddrs(input.Session, &ApplyRemoveNetsInput{
		BaseCLIInput: input.BaseCLIInput,
		MatchPrefix:  input.MatchPrefix,
		RID:          policyID,
		Output:       input.Quiet,
		DryRun:       input.DryRun,
		Filepath:     input.Filepath,
		Action:       input.Action,
		Addrs:        input.Nets,
		MaxRules:     0,
		LogLevel:     input.LogLevel,
	})

	return results, err
}

// getNetsToRemove adds the IPs from the specified file to the list of IPs to remove
func getNetsToRemove(path string, inNets IPNets) (outNets IPNets, err error) {
	if path != "" {
		var fipns IPNets

		fipns, err = loadIPsFromPath(path)
		if err != nil {
			return
		}

		outNets = fipns
	}

	outNets = append(outNets, inNets...)

	if len(outNets) == 0 {
		err = errors.New("no ips to unblock provided")
	}

	return outNets, err
}

type ApplyRemoveNetsResult struct {
	Addr     netip.Prefix
	PolicyID string
	Removed  bool
}
type ApplyRemoveNetsResults []ApplyRemoveNetsResult

// getLowestPriority returns the lowest priority assigned to a rule starting with the specified prefix
func getLowestPriority(rules []*armfrontdoor.CustomRule, prefix RuleNamePrefix) (lowest int32) {
	var hadPrefixMatch bool

	for x := range rules {
		// if the custom rule is not a block rule, then add (remove all existing block rules)
		if strings.HasPrefix(*rules[x].Name, string(prefix)) {
			// if it's zero then we have our lowest
			if *rules[x].Priority == 0 {
				break
			}

			// if it's the first one, then set this as the start priority
			if !hadPrefixMatch {
				hadPrefixMatch = true

				lowest = *rules[x].Priority
			}

			// set lowest if priority is lower
			if *rules[x].Priority < lowest {
				lowest = *rules[x].Priority
			}
		}
	}

	return lowest
}

// ApplyRemoveAddrs removes selected networks from custom rules
func ApplyRemoveAddrs(s *session.Session, input *ApplyRemoveNetsInput) (results []ApplyRemoveNetsResult, err error) {
	lowercaseAction := strings.ToLower(actionBlock)

	inNets, err := getNetsToRemove(input.Filepath, input.Addrs)
	if err != nil {
		return
	}

	var p *armfrontdoor.WebApplicationFirewallPolicy

	// check if Policy exists
	p, err = GetRawPolicy(s, input.RID.SubscriptionID, input.RID.ResourceGroup, input.RID.Name)
	if err != nil {
		return nil, err
	}

	if p.Name == nil {
		return nil, fmt.Errorf("specified policy not found")
	}

	// take a copy of the Policy for later comparison
	originalPolicy, err := CopyPolicy(*p)
	if err != nil {
		return
	}

	// get a copy of the existing ipnets for the specified action and remove the specified list of nets
	existingNets, err := getIPNetsForPrefix(p, input.MatchPrefix, &input.Action)
	if err != nil {
		return
	}

	logrus.Tracef("existing %s nets: %d", input.MatchPrefix, len(existingNets))

	var trimmed []netip.Prefix

	// get networks being removed or not
	for _, inNet := range inNets {
		if slices.Contains(existingNets, inNet) {
			results = append(results, ApplyRemoveNetsResult{
				Addr:     inNet,
				PolicyID: input.RID.Raw,
				Removed:  true,
			})
		} else {
			results = append(results, ApplyRemoveNetsResult{
				Addr:     inNet,
				PolicyID: input.RID.Raw,
				Removed:  false,
			})
		}
	}

	for _, n := range existingNets {
		// check net to remove in existing nets
		if !slices.Contains(inNets, n) {
			// no match, so retain
			trimmed = append(trimmed, n)
		}
	}

	proposedRules, err := GenCustomRulesFromIPNets(
		trimmed,
		input.MaxRules,
		input.Action,
		input.MatchPrefix,
		int(getLowestPriority(p.Properties.CustomRules.Rules, input.MatchPrefix)))
	if err != nil {
		return
	}

	// remove existing block net rules from Policy before adding New
	var ecrs []*armfrontdoor.CustomRule

	for _, existingCustomRule := range p.Properties.CustomRules.Rules {
		// if the custom rule is not a block rule, then add (remove all existing block rules)
		if !strings.HasPrefix(*existingCustomRule.Name, string(input.MatchPrefix)) {
			ecrs = append(ecrs, existingCustomRule)
		}
	}

	// add proposed rules to the custom rules that have existing blocks removed
	// effectively replacing all existing block rules with our new proposed set of block rules: existing minus those to remove (unblock)
	ecrs = append(ecrs, proposedRules...)

	sort.Slice(ecrs, func(i, j int) bool {
		return *ecrs[i].Priority < *ecrs[j].Priority
	})

	// add the New Custom rules to the existing
	p.Properties.CustomRules.Rules = ecrs

	// check we don't exceed Azure rules limit
	if len(p.Properties.CustomRules.Rules) > MaxCustomRules {
		return nil, fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	}

	gppO, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: originalPolicy, New: *p})
	if err != nil {
		return nil, err
	}

	if gppO.CustomRuleChanges == 0 {
		logrus.Debug("nothing to do")

		return results, nil
	}

	if input.DryRun {
		logrus.Infof("%s | %d changes to %s list would be applied\n", GetFunctionName(), gppO.CustomRuleChanges, lowercaseAction)

		return results, nil
	}

	np, err := json.Marshal(p)
	if err != nil {
		return
	}

	logrus.Debugf("calling compare with original %d bytes and new %d bytes", 1, 2)

	diffsFound, err := compare(&originalPolicy, np)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("diffsFound: %t", diffsFound)

	logrus.Printf("updating policy %s", *p.Name)

	err = PushPolicy(s, &PushPolicyInput{
		Name:          *p.Name,
		Subscription:  input.RID.SubscriptionID,
		ResourceGroup: input.RID.ResourceGroup,
		Policy:        *p,
	})

	return results, err
}

type UpdatePolicyCustomRulesIPMatchPrefixesInput struct {
	BaseCLIInput
	Policy         *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID string
	RawResourceID  string
	ResourceID     config.ResourceID
	Action         armfrontdoor.ActionType
	Output         bool
	Filepath       string
	Addrs          IPNets
	RuleNamePrefix RuleNamePrefix
	PriorityStart  int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

func loadLocalPrefixes(filepath string, prefixes IPNets) (res IPNets, err error) {
	if filepath != "" {
		res, err = loadIPsFromPath(filepath)
		if err != nil {
			return
		}
	}

	res = append(res, prefixes...)

	if len(res) == 0 {
		return prefixes, errors.New("no local prefixes loaded")
	}

	return res, nil
}

type RuleNamePrefix string

var ruleNamePrefixTestStartNumber = regexp.MustCompile(`^[0-9].*`)
var ruleNamePrefixTestEndNumber = regexp.MustCompile(`^[a-zA-Z]+[0-9]+$`)

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

// UpdatePolicyCustomRulesIPMatchPrefixes updates an existing Custom Policy with prefixes matching the requested action
func UpdatePolicyCustomRulesIPMatchPrefixes(in UpdatePolicyCustomRulesIPMatchPrefixesInput) (modified bool, patch GeneratePolicyPatchOutput, err error) {
	funcName := GetFunctionName()

	if in.Policy == nil {
		return false, patch, fmt.Errorf("%s - policy is nil", funcName)
	}

	if in.LogLevel != nil {
		logrus.SetLevel(*in.LogLevel)
	}

	if slices.Contains([]armfrontdoor.ActionType{armfrontdoor.ActionTypeBlock, armfrontdoor.ActionTypeLog, armfrontdoor.ActionTypeRedirect}, in.Action) {
		if err = in.RuleNamePrefix.Check(); err != nil {
			return modified, patch, err
		}
	}

	if in.Policy == nil {
		return modified, patch, fmt.Errorf("missing policy")
	}

	if in.Policy.Properties == nil {
		return modified, patch, fmt.Errorf("policy missing properties")
	}

	prefixes, err := loadLocalPrefixes(in.Filepath, in.Addrs)
	if err != nil {
		return false, patch, err
	}

	// take a copy of the Policy for later comparison
	originalPolicy, err := CopyPolicy(*in.Policy)
	if err != nil {
		return modified, patch, err
	}

	// get a copy of the existing ipnets for the specified action and append to the list of new nets
	existingAddrs, err := getIPNetsForPrefix(in.Policy, in.RuleNamePrefix, &in.Action)
	if err != nil {
		return modified, patch, err
	}

	prefixes = append(prefixes, existingAddrs...)

	crs, err := GenCustomRulesFromIPNets(prefixes, in.MaxRules, in.Action, in.RuleNamePrefix, in.PriorityStart)
	if err != nil {
		return
	}

	// newPrioritiesEnd := in.PriorityStart + len(crs)

	// remove existing net rules from Policy before adding New
	var ecrs []*armfrontdoor.CustomRule

	for _, existingCustomRule := range in.Policy.Properties.CustomRules.Rules {
		// if New Custom rule name doesn't have the prefix in the Action, then add it
		if !strings.HasPrefix(*existingCustomRule.Name, string(in.RuleNamePrefix)) {
			// check new rule priority is not already in use
			// START TEST
			// if *existingCustomRule.Priority >= int32(in.PriorityStart) {
			// 	fmt.Println("DDD")
			// }
			// if *existingCustomRule.Priority <= int32(newPrioritiesEnd) {
			// 	fmt.Println(*existingCustomRule.Priority, int32(newPrioritiesEnd))
			// }

			ecrs = append(ecrs, existingCustomRule)

			continue
		}
	}

	// add the New Custom rules to the existing
	in.Policy.Properties.CustomRules.Rules = ecrs
	in.Policy.Properties.CustomRules.Rules = append(in.Policy.Properties.CustomRules.Rules, crs...)
	o, _ := json.MarshalIndent(in.Policy.Properties.CustomRules.Rules, "", "  ")

	// check we don't exceed Azure rules limit
	if len(in.Policy.Properties.CustomRules.Rules) > MaxCustomRules {
		return modified, patch, fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	}

	// sort rules by priority
	sort.Slice(in.Policy.Properties.CustomRules.Rules, func(i, j int) bool {
		return *in.Policy.Properties.CustomRules.Rules[i].Priority < *in.Policy.Properties.CustomRules.Rules[j].Priority
	})

	patch, err = GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: originalPolicy, New: *in.Policy})
	if err != nil {
		return modified, patch, err
	}

	o, _ = json.Marshal(patch)
	fmt.Println(string(o))

	if patch.TotalDifferences == 0 {
		logrus.Debug("nothing to do")

		return
	}

	if patch.ManagedRuleChanges != 0 {
		return true, patch, fmt.Errorf("unexpected Managed rules changes. aborting")
	}

	return true, patch, nil
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
func deDupeIPNets(ipns IPNets) (res []string) {
	// check overlaps
	seen := make(map[string]bool)

	for _, i := range ipns.toString() {
		if _, ok := seen[i]; ok {
			continue
		}

		res = append(res, i)
		seen[i] = true
	}

	return
}

// TODO: need to support more than just IP
// TODO: add support for transforms
// createCustomRule will return a frontdoor CustomRule constructed from the provided input
func createCustomRule(name string, action armfrontdoor.ActionType, priority int32, items []*string) armfrontdoor.CustomRule {
	f := false
	rt := armfrontdoor.RuleTypeMatchRule
	es := armfrontdoor.CustomRuleEnabledStateEnabled
	mv := armfrontdoor.MatchVariableRemoteAddr
	op := armfrontdoor.OperatorIPMatch
	// at := armfrontdoor.ActionType(action)
	tt := []*armfrontdoor.TransformType{}

	nameWithPriority := fmt.Sprintf("%s%d", name, priority)

	return armfrontdoor.CustomRule{
		Name:         &nameWithPriority,
		Priority:     &priority,
		EnabledState: &es,
		RuleType:     &rt,
		MatchConditions: []*armfrontdoor.MatchCondition{{
			MatchVariable:   &mv,
			NegateCondition: &f,
			Operator:        &op,
			MatchValue:      items,
			Transforms:      tt,
		}},

		Action: &action,
	}
}

func strsTostrPtrs(in []string) (out []*string) {
	for i := range in {
		out = append(out, &in[i])
	}

	return
}

// GenCustomRulesFromIPNets accepts a list of IPs, plus the action to be taken with them, and the maximum
// number of rules to create and then returns a slice of CustomRules
func GenCustomRulesFromIPNets(ipns IPNets, maxRules int, action armfrontdoor.ActionType, customNamePrefix RuleNamePrefix, customPriorityStart int) (crs []*armfrontdoor.CustomRule, err error) {
	if !slices.Contains(armfrontdoor.PossibleActionTypeValues(), action) {
		return nil, fmt.Errorf("invalid action: %s", action)
	}

	var priorityStart int

	if customPriorityStart != 0 {
		priorityStart = customPriorityStart
	}

	deDupedNets := deDupeIPNets(ipns)

	logrus.Tracef("total networks after deduplication: %d", len(deDupedNets))

	strDeDupedNets := deDupedNets

	priorityCount := int32(priorityStart)

	var lastChunkEnd int

	var matchValues []string

	var customRulesGenerated int32

	for x := range strDeDupedNets {
		if x > 0 && x%MaxIPMatchValues == 0 {
			matchValues = strDeDupedNets[x-MaxIPMatchValues : x]
			lastChunkEnd = x
		} else if x+1 == len(strDeDupedNets) {
			matchValues = strDeDupedNets[lastChunkEnd:]
		}

		if len(matchValues) > 0 {
			bic := createCustomRule(string(customNamePrefix), action, priorityCount, strsTostrPtrs(matchValues))

			priorityCount++

			crs = append(crs, &bic)

			customRulesGenerated++
			if customRulesGenerated > 0 && customRulesGenerated == int32(maxRules) {
				return
			}

			// reset matchValues
			matchValues = nil
		}
	}

	return
}

// readIPsFromFile accepts a file path from which to load IPs (one per line) as strings and return a slice of
func readIPsFromFile(fPath string) (ipnets IPNets, err error) {
	// #nosec
	file, err := os.Open(fPath)
	if err != nil {
		log.Fatalf("failed to open")
	}

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
				return
			}

			ipnets = append(ipnets, ipnet)
		}
	}

	return
}

// loadIPsFromPath accepts a file path or directory and then generates a fully qualified path
// in order to call a function to load the ips from each fully qualified file path
func loadIPsFromPath(path string) (ipNets IPNets, err error) {
	// if path is a folder, then loop through contents
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}

	if info.IsDir() {
		var files []os.DirEntry

		files, err = os.ReadDir(path)
		if err != nil {
			return
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
				return
			}

			logrus.Infof("loaded %d ips from file %s", len(n), p)

			ipNets = append(ipNets, n...)
		}

		return
	}

	var n IPNets

	n, err = readIPsFromFile(path)
	if err != nil {
		return
	}

	logrus.Debugf("loaded %d ips from file %s", len(n), path)

	ipNets = append(ipNets, n...)

	return
}

type AddCustomRulesPrefixesInput struct {
	BaseCLIInput
	Session        *session.Session
	Policy         *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID string
	RawResourceID  string
	ResourceID     config.ResourceID
	Action         armfrontdoor.ActionType
	Output         bool
	DryRun         bool
	Filepath       string
	Addrs          IPNets
	RuleNamePrefix RuleNamePrefix
	PriorityStart  int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

// matchConditionValidForUnblock returns true if removal of a prefix will mean unblocking the prefix
func matchConditionValidForUnblock(mc *armfrontdoor.MatchCondition) bool {
	// if the condition is negated then it's a negative match and removal will not mean unblocking
	if *mc.NegateCondition {
		logrus.Debugf("match condition is negated so not valid for unblock")
		return false
	}

	// removing a prefix is only valid for remote or socket address
	if !slices.Contains([]armfrontdoor.MatchVariable{armfrontdoor.MatchVariableRemoteAddr, armfrontdoor.MatchVariableSocketAddr}, *mc.MatchVariable) {
		logrus.Warnf("match condition is not remote address nor socket address so not valid for unblock")
		return false
	}

	if *mc.Operator != armfrontdoor.OperatorIPMatch {
		logrus.Warnf("match condition operator not ip match so not valid for unblock")
		return false
	}

	return true
}

func tryNetStrToPrefix(inNetStr string) (prefix netip.Prefix, err error) {
	// if no mask then try parsing as address
	if !strings.Contains(inNetStr, "/") {
		addr, pErr := netip.ParseAddr(inNetStr)
		if pErr != nil {
			return prefix, pErr
		}

		return addr.Prefix(addr.BitLen())
	}

	return netip.ParsePrefix(inNetStr)
}
