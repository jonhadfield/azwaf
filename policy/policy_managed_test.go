package policy

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/stretchr/testify/require"
)

func TestGetPolicyStatsWithoutPolicy(t *testing.T) {
	defs, err := LoadManagedRulesetDefinitions()
	require.NoError(t, err)
	stats, err := getPolicyStats(nil, defs)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), errPolicyNotDefined)
	require.Empty(t, stats)
}

func TestGetPolicyStatsWithoutDefinitions(t *testing.T) {
	p, err := LoadPolicyFromFile("testdata/test-policy-one.json")
	require.NoError(t, err)

	var defs []*armfrontdoor.ManagedRuleSetDefinition

	stats, err := getPolicyStats(&p, defs)
	require.NotNil(t, err)
	require.Empty(t, stats)
}

func TestGetPolicyStats(t *testing.T) {
	p, err := LoadPolicyFromFile("testdata/test-policy-one.json")

	require.NoError(t, err)

	defs, err := LoadManagedRulesetDefinitions()

	require.NoError(t, err)

	stats, err := getPolicyStats(&p, defs)

	require.NoError(t, err)
	require.Equal(t, "Microsoft_DefaultRuleSet", stats[0].RuleSetType)
	require.Equal(t, "1.1", stats[0].RuleSetVersion)
	require.Equal(t, 64, stats[0].TotalExclusions)
	require.Equal(t, 50, stats[0].RuleScopeExclusionsTotal)
	require.Equal(t, 10, stats[0].RuleGroupScopeExclusionsTotal)
	require.Equal(t, 4, stats[0].RuleSetScopeExclusionsTotal)
	require.Equal(t, 13, stats[0].GroupCount)
	require.Equal(t, 124, stats[0].Rules)
	require.Equal(t, 119, stats[0].RulesEnabled)
	require.Equal(t, 5, stats[0].RulesDisabled)
	require.Equal(t, 4, stats[0].RulesDefaultEnabledStateOveridden)
	require.Equal(t, 36, stats[0].RulesDefaultActionOveridden)
	require.Equal(t, 88, stats[0].BlockTotal)
	require.Equal(t, 1, stats[0].AllowTotal)
	require.Equal(t, 34, stats[0].LogTotal)
	require.Equal(t, 1, stats[0].RedirectTotal)
	require.Equal(t, 13, stats[0].GroupCount)
}

func TestNormaliseMatchOperator(t *testing.T) {
	// exact
	matches, result := NormaliseMatchOperator("Equals")
	require.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEquals, result)
	require.True(t, matches)

	// invalid
	matches, result = NormaliseMatchOperator("Has")
	require.False(t, matches)
	require.Empty(t, result)

	// mixed case
	matches, result = NormaliseMatchOperator("conTaIns")
	require.True(t, matches)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorContains, result)
}

func TestNormaliseMatchVariable(t *testing.T) {
	// exact
	matches, result := NormaliseMatchVariable("RequestCookieNames")
	require.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestCookieNames, result)
	require.True(t, matches)

	// invalid
	matches, result = NormaliseMatchVariable("x-forward-for")
	require.False(t, matches)
	require.Empty(t, result)

	// mixed case
	matches, result = NormaliseMatchVariable("requestHeadernames")
	require.True(t, matches)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames, result)
}
