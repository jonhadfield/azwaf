package policy

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/logging"
	"github.com/jonhadfield/azwaf/session"
)

type customRuleMatchesNameOrPriorityInput struct {
	prioritySet bool
	nameMatch   *regexp.Regexp
	// name        string
	priority int
}

func customRuleMatchesNameOrPriority(mi customRuleMatchesNameOrPriorityInput, cr *armfrontdoor.CustomRule) bool {
	// check where a priority was provided and a name match exists
	if mi.prioritySet && mi.nameMatch != nil {
		if mi.nameMatch.MatchString(*cr.Name) && int32(mi.priority) == *cr.Priority {
			return false
		}

		return true
	}

	// check where a priority was provided (name match isn't set)
	if mi.prioritySet {
		return int32(mi.priority) != *cr.Priority
	}

	// if regex provided then test against name
	if mi.nameMatch != nil {
		return !mi.nameMatch.MatchString(*cr.Name)
	}

	// shouldn't have any other scenarios: log it, and keep the rule rather
	// than deleting on an undefined match
	logging.Error("custom rule matcher called without name and priority")

	return false
}

func stripCustomRulesMatchingNameOrPriority(prioritySet bool, priority int, nameMatch *regexp.Regexp, ecrs []*armfrontdoor.CustomRule) []*armfrontdoor.CustomRule {
	var res []*armfrontdoor.CustomRule

	for _, cr := range ecrs {
		if customRuleMatchesNameOrPriority(customRuleMatchesNameOrPriorityInput{
			prioritySet: prioritySet,
			priority:    priority,
			nameMatch:   nameMatch,
		}, cr) {

			res = append(res, cr)
		}
	}

	return res
}

func checkDebug(d bool) {
	if d {
		logging.SetLevel(slog.LevelDebug)
	}
}

func (input *DeleteCustomRulesCLIInput) ParseConfig() (output DeleteCustomRulesPrefixesInput, err error) {
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

func DeleteCustomRulesPrefixes(in DeleteCustomRulesPrefixesInput) (modified bool, err error) {
	funcName := GetFunctionName()

	if in.Policy == nil {
		return false, fmt.Errorf("%s - missing policy from input", funcName)
	}

	// create a copy for later comparison
	policyCopy, err := CopyPolicy(*in.Policy)
	if err != nil {
		return
	}

	// remove all but those starting with supplied prefix
	preLen := len(policyCustomRules(&policyCopy))

	// generate slice of existing Custom rules that do NOT match the regex nor priority
	ecrs := stripCustomRulesMatchingNameOrPriority(in.PrioritySet, in.Priority, in.NameMatch, policyCustomRules(in.Policy))
	if len(ecrs) == preLen {
		logging.Debug("nothing to do")

		return modified, nil
	}

	// sort rules by priority
	sort.Slice(ecrs, func(i, j int) bool {
		return *ecrs[i].Priority < *ecrs[j].Priority
	})

	in.Policy.Properties.CustomRules.Rules = ecrs

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: policyCopy,
		New:      *in.Policy,
	})
	if err != nil {
		return
	}

	if patch.TotalDifferences == 0 {
		logging.Debug("nothing to do")

		return
	}

	if patch.ManagedRuleChanges != 0 {
		return false, fmt.Errorf("unexpected Managed rules changes. aborting")
	}

	return true, nil
}

func DeleteCustomRulesCLI(cliInput *DeleteCustomRulesCLIInput) (err error) {
	funcName := GetFunctionName()

	s := cliInput.Session
	if s == nil {
		if s, err = session.New(); err != nil {
			return err
		}
	}

	policyID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: cliInput.SubscriptionID,
		RawPolicyID:    cliInput.PolicyID,
		ConfigPath:     cliInput.ConfigPath,
	})
	if err != nil {
		return err
	}

	dcri, err := cliInput.ParseConfig()
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	getPolicyInput := GetPolicyInput{
		Session:  s,
		PolicyID: policyID,
	}

	getPolicyOutput, err := getPolicyInput.GetPolicy()
	if err != nil {
		return
	}

	var modified bool
	if modified, err = DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
		RID:         policyID,
		Policy:      getPolicyOutput.Policy,
		Debug:       dcri.Debug,
		MaxRules:    dcri.MaxRules,
		Priority:    dcri.Priority,
		PrioritySet: dcri.PrioritySet,
		Name:        dcri.Name,
		NameMatch:   dcri.NameMatch,
	}); err != nil {
		return
	}

	if !modified {
		logging.Info("no change necessary")

		return
	}

	return ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       *getPolicyOutput.Policy.Name,
		SubscriptionID:   policyID.SubscriptionID,
		ResourceGroup:    policyID.ResourceGroup,
		PolicyPostChange: *getPolicyOutput.Policy,
		DryRun:           cliInput.DryRun,
		Backup:           cliInput.AutoBackup,
		Debug:            dcri.Debug,
	})
}
