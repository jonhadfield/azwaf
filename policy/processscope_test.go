package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Both scope functions run the same cascade over the same three selectors.
// This pins the scope each combination produces, for both, before they were
// collapsed onto one implementation.
func TestProcessScopeCombinations(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		ruleSetType, ruleGroup, rule string
		want                         ExclusionScope
	}{
		{"rule id alone", "", "", "942100", ScopeRule},
		{"rule id wins over everything", "rs", "grp", "942100", ScopeRule},
		{"rule set alone", "rs", "", "", ScopeRuleSet},
		{"rule group alone", "", "grp", "", ScopeRuleGroup},
		{"rule set and group", "rs", "grp", "", ScopeRuleGroup},
	} {
		t.Run("delete/"+tc.name, func(t *testing.T) {
			got, err := GetDeleteManagedRuleExclusionProcessScope(&DeleteManagedRuleExclusionInput{
				RuleSetType: toPtr(tc.ruleSetType),
				RuleGroup:   tc.ruleGroup,
				RuleID:      tc.rule,
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})

		t.Run("add/"+tc.name, func(t *testing.T) {
			got, err := GetAddManagedRuleExclusionProcessScope(AddManagedRuleExclusionInput{
				RuleSetType:    toPtr(tc.ruleSetType),
				RuleSetVersion: toPtr("2.1"),
				RuleGroup:      tc.ruleGroup,
				RuleID:         tc.rule,
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// With no selectors at all neither can determine a scope. The two word the
// error differently, which the collapse preserves.
func TestProcessScopeRequiresASelector(t *testing.T) {
	_, err := GetDeleteManagedRuleExclusionProcessScope(&DeleteManagedRuleExclusionInput{
		RuleSetType: toPtr(""),
	})
	require.ErrorContains(t, err, "a rule id, rule group, or rule set was not provided")

	_, err = GetAddManagedRuleExclusionProcessScope(AddManagedRuleExclusionInput{
		RuleSetType:    toPtr(""),
		RuleSetVersion: toPtr(""),
	})
	require.ErrorContains(t, err, "rule id, rule group, and rule set are required")
}

// Both take the rule set as a pointer and neither guarded it consistently: the
// delete side checked for nil once and then dereferenced it anyway, and the add
// side dereferenced before checking anything.
func TestProcessScopeToleratesNilRuleSet(t *testing.T) {
	t.Run("delete with a rule group and no rule set", func(t *testing.T) {
		require.NotPanics(t, func() {
			got, err := GetDeleteManagedRuleExclusionProcessScope(&DeleteManagedRuleExclusionInput{
				RuleSetType: nil,
				RuleGroup:   "grp",
			})
			require.NoError(t, err)
			require.Equal(t, ScopeRuleGroup, got)
		})
	})

	t.Run("add with nothing set", func(t *testing.T) {
		require.NotPanics(t, func() {
			_, err := GetAddManagedRuleExclusionProcessScope(AddManagedRuleExclusionInput{})
			require.Error(t, err, "no selectors, so no scope")
		})
	})

	t.Run("add with a rule group and no rule set", func(t *testing.T) {
		require.NotPanics(t, func() {
			got, err := GetAddManagedRuleExclusionProcessScope(AddManagedRuleExclusionInput{
				RuleGroup: "grp",
			})
			require.NoError(t, err)
			require.Equal(t, ScopeRuleGroup, got)
		})
	})
}
