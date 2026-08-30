package policy

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/helpers"
)

type RuleSetStatsOutput struct {
	// rule set
	RuleSetType    string
	RuleSetVersion string

	// rules
	Rules                             int
	RulesEnabled                      int
	RulesDisabled                     int
	RulesDefaultEnabledStateOveridden int
	RulesDefaultActionOveridden       int
	BlockTotal                        int
	AllowTotal                        int
	LogTotal                          int
	RedirectTotal                     int
	GroupCount                        int

	// exclusions
	RuleSetScopeExclusionsTotal   int
	RuleGroupScopeExclusionsTotal int
	RuleScopeExclusionsTotal      int
	TotalExclusions               int
}

// getPolicyStats returns counts for all items in a rule set
func getPolicyStats(policy *armfrontdoor.WebApplicationFirewallPolicy, mrsd []*armfrontdoor.ManagedRuleSetDefinition) ([]RuleSetStatsOutput, error) {
	funcName := helpers.GetFunctionName()

	var stats []RuleSetStatsOutput

	if len(policyManagedRuleSets(policy)) == 0 {
		return stats, fmt.Errorf("%s - policy not defined", funcName)
	}

	if len(mrsd) == 0 || mrsd[0].Properties == nil {
		return stats, fmt.Errorf("%s - managed ruleset definitions not provided", funcName)
	}

	for _, rs := range policyManagedRuleSets(policy) {
		rs := rs
		matchingDefinitionsOutput := getDefinitionMatchingExistingRuleSets(&getDefinitionsMatchingExistingRuleSetsInput{
			mrsdl:          mrsd,
			ruleSetType:    *rs.RuleSetType,
			ruleSetVersion: *rs.RuleSetVersion,
		})

		if matchingDefinitionsOutput.RuleSetDefinition == nil {
			return stats, fmt.Errorf("%s - failed to get matching definition for rule set %s_%s",
				funcName, *rs.RuleSetType, *rs.RuleSetVersion)
		}

		stats = append(stats, getRuleSetStats(rs, matchingDefinitionsOutput.RuleSetDefinition))
	}

	return stats, nil
}
