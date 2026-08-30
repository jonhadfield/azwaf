package policy

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/stretchr/testify/require"
)

// The rendered names are user-visible, in the shadows table and in the
// add-exclusion summary. Pinned before scope became a named type.
func TestExclusionScopeRendering(t *testing.T) {
	for _, tc := range []struct {
		scope ExclusionScope
		title string
		lower string
	}{
		{ScopeRule, "Rule", "rule"},
		{ScopeRuleGroup, "Rule Group", "rule group"},
		{ScopeRuleSet, "Rule Set", "rule set"},
		{ExclusionScope("nonsense"), "", ""},
		{ExclusionScope(""), "", ""},
	} {
		require.Equal(t, tc.title, tc.scope.Title(), "title for %q", tc.scope)
		require.Equal(t, tc.lower, tc.scope.Lower(), "lower for %q", tc.scope)
	}
}

// The wire values are what the derivation functions return and what the
// comparisons match on, so they are part of the contract.
func TestExclusionScopeWireValues(t *testing.T) {
	require.Equal(t, ExclusionScope("rule"), ScopeRule)
	require.Equal(t, ExclusionScope("ruleGroup"), ScopeRuleGroup)
	require.Equal(t, ExclusionScope("ruleSet"), ScopeRuleSet)
}

// Both flows overwrite Scope from the selectors before reading it, so a value
// set by a caller never survives to be compared. This is what makes exact
// comparison safe where the code previously mixed == with strings.EqualFold.
func TestScopeIsDerivedNotAccepted(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		in := &DeleteManagedRuleExclusionInput{
			Scope:     ExclusionScope("WHATEVER-THE-CALLER-SET"),
			RuleGroup: "SQLI",
		}

		got, err := GetDeleteManagedRuleExclusionProcessScope(in)
		require.NoError(t, err)
		require.Equal(t, ScopeRuleGroup, got, "derived from the selectors, not from Scope")
	})

	t.Run("add", func(t *testing.T) {
		in := AddManagedRuleExclusionInput{
			Scope:  ExclusionScope("WHATEVER-THE-CALLER-SET"),
			RuleID: "942100",
		}

		got, err := GetAddManagedRuleExclusionProcessScope(in)
		require.NoError(t, err)
		require.Equal(t, ScopeRule, got)
	})
}

// The narrowest selector wins, regardless of what else is set.
func TestScopeFromSelectorsPrecedence(t *testing.T) {
	for _, tc := range []struct {
		ruleSetType, ruleGroup, ruleID string
		want                           ExclusionScope
		ok                             bool
	}{
		{"OWASP", "SQLI", "942100", ScopeRule, true},
		{"OWASP", "SQLI", "", ScopeRuleGroup, true},
		{"", "SQLI", "", ScopeRuleGroup, true},
		{"OWASP", "", "", ScopeRuleSet, true},
		{"", "", "", ExclusionScope(""), false},
	} {
		got, ok := scopeFromSelectors(tc.ruleSetType, tc.ruleGroup, tc.ruleID)
		require.Equal(t, tc.ok, ok)
		require.Equal(t, tc.want, got)
	}
}

// The exclusion scopes read off a policy feed the limit messages, so they carry
// the lowercase rendering rather than the wire value.
func TestPolicyExclusionScopesUseRenderedNames(t *testing.T) {
	excl := []*armfrontdoor.ManagedRuleExclusion{{
		MatchVariable:         toPtr(armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames),
		SelectorMatchOperator: toPtr(armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEquals),
		Selector:              toPtr("x"),
	}}

	p := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{{
					RuleSetType:    toPtr("OWASP"),
					RuleSetVersion: toPtr("3.2"),
					Exclusions:     excl,
					RuleGroupOverrides: []*armfrontdoor.ManagedRuleGroupOverride{{
						RuleGroupName: toPtr("SQLI"),
						Exclusions:    excl,
						Rules: []*armfrontdoor.ManagedRuleOverride{{
							RuleID:     toPtr("942100"),
							Exclusions: excl,
						}},
					}},
				}},
			},
		},
	}

	var got []string
	for _, s := range policyExclusionScopes(p) {
		got = append(got, s.scope.Lower())
	}

	require.ElementsMatch(t, []string{"rule set", "rule group", "rule"}, got,
		"one entry per scope, named as the limit messages render them")
}
