package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/internal/azfakes"
	"github.com/stretchr/testify/require"
)

func exclusionsForTest(n int) []*armfrontdoor.ManagedRuleExclusion {
	mv := armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames
	mo := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEquals

	out := make([]*armfrontdoor.ManagedRuleExclusion, 0, n)
	for i := range n {
		out = append(out, &armfrontdoor.ManagedRuleExclusion{
			MatchVariable:         &mv,
			Selector:              toPtr(fmt.Sprintf("h%d", i)),
			SelectorMatchOperator: &mo,
		})
	}

	return out
}

// policyWithExclusions builds a policy holding the given number of exclusions
// at each of the three scopes.
func policyWithExclusions(ruleSet, ruleGroup, rule int) *armfrontdoor.WebApplicationFirewallPolicy {
	return &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("Microsoft_DefaultRuleSet"),
						RuleSetVersion: toPtr("2.1"),
						Exclusions:     exclusionsForTest(ruleSet),
						RuleGroupOverrides: []*armfrontdoor.ManagedRuleGroupOverride{
							{
								RuleGroupName: toPtr("SQLI"),
								Exclusions:    exclusionsForTest(ruleGroup),
								Rules: []*armfrontdoor.ManagedRuleOverride{
									{RuleID: toPtr("942100"), Exclusions: exclusionsForTest(rule)},
								},
							},
						},
					},
				},
			},
		},
	}
}

// The limit is 100 per scope, but the check summed all three and compared the
// total against it. 40 in each scope totals 120 and was reported as a breach,
// though no scope is near its own limit.
func TestExclusionLimitIsPerScopeNotTotal(t *testing.T) {
	p := policyWithExclusions(40, 40, 40)

	require.NoError(t, validatePolicyLimits(p),
		"three scopes of 40 are all well inside the per-scope limit")

	require.Empty(t, exclusionLimitWarnings(p),
		"no scope is near its limit, so nothing should be reported")
}

// The mirror case: a single scope over the limit must be caught, even though
// the combined total is lower than the false-alarm case above.
func TestExclusionLimitCaughtAtASingleScope(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		ruleSet, group, rule    int
		wantScope, wantScopeStr string
	}{
		{"rule set scope", maxExclusionLimit + 1, 0, 0, "rule set", "Microsoft_DefaultRuleSet_2.1"},
		{"rule group scope", 0, maxExclusionLimit + 1, 0, "rule group", "SQLI"},
		{"rule scope", 0, 0, maxExclusionLimit + 1, "rule", "942100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := policyWithExclusions(tc.ruleSet, tc.group, tc.rule)

			err := validatePolicyLimits(p)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.wantScope)
			require.ErrorContains(t, err, tc.wantScopeStr)
			require.ErrorContains(t, err, "exceeding Azure's limit of 100 per scope")
		})
	}
}

// Exactly at the limit is allowed; the warning still flags it.
func TestExclusionLimitBoundary(t *testing.T) {
	at := policyWithExclusions(maxExclusionLimit, 0, 0)
	require.NoError(t, validatePolicyLimits(at), "100 is the limit, not one past it")

	warnings := exclusionLimitWarnings(at)
	require.Len(t, warnings, 1)
	require.True(t, warnings[0].atLimit)
	require.Contains(t, warnings[0].message, "has reached the maximum exclusion limit")
	require.Contains(t, warnings[0].message, "100/100")

	// and one below the warning threshold stays quiet
	quiet := policyWithExclusions(maxExclusionLimitWarningThreshold-1, 0, 0)
	require.Empty(t, exclusionLimitWarnings(quiet))
}

// Approaching the limit warns, naming the scope that is filling up.
func TestExclusionLimitWarningNamesTheScope(t *testing.T) {
	p := policyWithExclusions(0, maxExclusionLimitWarningThreshold, 0)

	warnings := exclusionLimitWarnings(p)
	require.Len(t, warnings, 1)
	require.False(t, warnings[0].atLimit, "95 approaches the limit, it does not reach it")
	require.Contains(t, warnings[0].message, "nearing maximum exclusion limit")
	require.Contains(t, warnings[0].message, "rule group")
	require.Contains(t, warnings[0].message, "SQLI")
	require.Contains(t, warnings[0].message, "95/100")
}

// The check was display-only: it fired while rendering show policy --stats and
// nothing consulted it before pushing. It now runs on the push path.
func TestExclusionLimitEnforcedBeforePushing(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	over := policyWithExclusions(maxExclusionLimit+1, 0, 0)
	over.Name = toPtr("fd-one")

	err = ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       "fd-one",
		SubscriptionID:   azfakesSubID,
		ResourceGroup:    "rg-one",
		PolicyPostChange: *over,
	})

	require.ErrorContains(t, err, "exceeding Azure's limit of 100 per scope")
	require.Empty(t, st.PushedFrontDoor(), "nothing should reach Azure")
}

// Bot rule sets are exempt from the warning.
func TestExclusionLimitSkipsBotRuleSets(t *testing.T) {
	p := policyWithExclusions(maxExclusionLimit, 0, 0)
	p.Properties.ManagedRules.ManagedRuleSets[0].RuleSetType = toPtr("Microsoft_BotManagerRuleSet")

	require.Empty(t, exclusionLimitWarnings(p))
	require.True(t, strings.Contains(ruleSetDisplayName(p.Properties.ManagedRules.ManagedRuleSets[0]), "Bot"))

	// and the printer runs over the same input without incident
	require.NotPanics(t, func() { warnOnExclusionLimits(p) })
}
