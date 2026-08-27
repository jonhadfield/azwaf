package policy

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/alexeyco/simpletable"
	"github.com/stretchr/testify/require"
)

// Policy fields arriving from the Azure API are pointers, and the rendering
// path dereferenced several of them unguarded — a policy missing any one of
// them crashed the process rather than showing a dash. These cover the fields
// reachable through `show policy`.

func TestValueOrDashHandlesNilTypedPointers(t *testing.T) {
	require.NotPanics(t, func() {
		require.Equal(t, "-", valueOrDash((*armfrontdoor.MatchVariable)(nil)))
		require.Equal(t, "-", valueOrDash((*armfrontdoor.Operator)(nil)))
		require.Equal(t, "-", valueOrDash((*string)(nil)))
		require.Equal(t, "-", valueOrDash(nil))
	})

	// non-nil values still render
	mv := armfrontdoor.MatchVariableRequestURI
	op := armfrontdoor.OperatorContains
	require.Equal(t, string(mv), valueOrDash(&mv))
	require.Equal(t, string(op), valueOrDash(&op))
	require.Equal(t, "x", valueOrDash(toPtr("x")))
}

func TestAppendCustomRuleRowsToleratesMissingFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule *armfrontdoor.CustomRule
	}{
		{"no name", &armfrontdoor.CustomRule{Priority: toPtr(int32(1))}},
		{"no priority", &armfrontdoor.CustomRule{Name: toPtr("R")}},
		{"no enabled state", &armfrontdoor.CustomRule{Name: toPtr("R"), Priority: toPtr(int32(1))}},
		{"nothing at all", &armfrontdoor.CustomRule{}},
		{"nil match condition fields", &armfrontdoor.CustomRule{
			Name:     toPtr("R"),
			Priority: toPtr(int32(1)),
			MatchConditions: []*armfrontdoor.MatchCondition{
				{MatchVariable: nil, Operator: nil, NegateCondition: nil},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				appendCustomRuleRows(simpletable.New(), tc.rule, false)
			})
		})
	}
}

func TestOutputPolicyMetaDataToleratesMissingFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy *armfrontdoor.WebApplicationFirewallPolicy
	}{
		{"no id", &armfrontdoor.WebApplicationFirewallPolicy{
			Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
				PolicySettings: &armfrontdoor.PolicySettings{},
			},
		}},
		{"no sku", &armfrontdoor.WebApplicationFirewallPolicy{
			ID: toPtr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/p"),
			Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
				PolicySettings: &armfrontdoor.PolicySettings{},
			},
		}},
		{"no policy settings", &armfrontdoor.WebApplicationFirewallPolicy{
			ID:         toPtr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/p"),
			Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{},
		}},
		{"no properties", &armfrontdoor.WebApplicationFirewallPolicy{
			ID: toPtr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/p"),
		}},
		{"nothing at all", &armfrontdoor.WebApplicationFirewallPolicy{}},
		{"nil policy", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				OutputPolicyMetaData(tc.policy)
			})
		})
	}
}

func TestSortCustomRulesByPriorityToleratesMissingPriority(t *testing.T) {
	rules := []*armfrontdoor.CustomRule{
		{Name: toPtr("b"), Priority: toPtr(int32(10))},
		{Name: toPtr("no-priority")},
		{Name: toPtr("a"), Priority: toPtr(int32(1))},
	}

	require.NotPanics(t, func() {
		sortCustomRulesByPriority(rules)
	})

	// rules without a priority sort first, and the rest stay ascending
	require.Equal(t, "no-priority", *rules[0].Name)
	require.Equal(t, "a", *rules[1].Name)
	require.Equal(t, "b", *rules[2].Name)
}

func TestPushPolicyToleratesPolicyWithoutName(t *testing.T) {
	// the debug log dereferenced *i.Policy.Name before anything validated it
	require.NotPanics(t, func() {
		_ = PushPolicy(nil, &PushPolicyInput{
			Name:          "fd-one",
			Subscription:  azfakesSubID,
			ResourceGroup: "rg-one",
			Policy:        armfrontdoor.WebApplicationFirewallPolicy{},
		})
	})
}

// `show policy` on a policy with no SKU crashed here before reaching the
// managed-rules table.
func TestOutputManagedRulesetsToleratesMissingSKU(t *testing.T) {
	require.NotPanics(t, func() {
		outputManagedRulesets(&armfrontdoor.WebApplicationFirewallPolicy{
			Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{},
		}, nil)
	})

	require.NotPanics(t, func() {
		outputManagedRulesets(nil, nil)
	})
}

// `list frontdoors` renders the policy each endpoint references; one without a
// name took the listing down.
func TestShowFrontDoorsToleratesUnnamedPolicy(t *testing.T) {
	require.NotPanics(t, func() {
		showFrontDoors(FrontDoors{
			{
				name: "fd-one",
				endpoints: []FrontDoorEndpoint{
					{name: "ep-one", wafPolicy: armfrontdoor.WebApplicationFirewallPolicy{}},
				},
			},
		})
	})
}

// --- copy and restore paths ---

func fdPolicyForNilSafety() armfrontdoor.WebApplicationFirewallPolicy {
	return armfrontdoor.WebApplicationFirewallPolicy{
		ID: toPtr(nilSafetyPolicyID),
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			CustomRules:  &armfrontdoor.CustomRuleList{Rules: []*armfrontdoor.CustomRule{{Name: toPtr("R")}}},
			ManagedRules: &armfrontdoor.ManagedRuleSetList{},
		},
	}
}

const nilSafetyPolicyID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/p"

// copyPolicyRules kept its nil-target check in the same switch as the
// managed-rules check, so the target arm was unreachable once an earlier arm
// matched and a nil target panicked. Missing Properties panicked too.
func TestCopyPolicyRulesReportsMissingPolicies(t *testing.T) {
	full := fdPolicyForNilSafety()
	noProps := armfrontdoor.WebApplicationFirewallPolicy{ID: toPtr(nilSafetyPolicyID)}

	for _, tc := range []struct {
		name           string
		source, target *armfrontdoor.WebApplicationFirewallPolicy
		wantErr        string
	}{
		{"nil source", nil, &full, "source policy is missing"},
		{"source without properties", &noProps, &full, "source policy is missing"},
		{"nil target", &full, nil, "target policy is missing"},
		{"target without properties", &full, &noProps, "target policy is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				source, target := tc.source, tc.target
				if source != nil {
					c := *source
					source = &c
				}

				if target != nil {
					c := *target
					target = &c
				}

				_, err := copyPolicyRules(source, target, false, false)
				require.ErrorContains(t, err, tc.wantErr)
			})
		})
	}
}

// BuildRestoredPolicy chained up to four optional pointers per assignment.
func TestBuildRestoredPolicyToleratesMissingRuleContainers(t *testing.T) {
	noProps := armfrontdoor.WebApplicationFirewallPolicy{ID: toPtr(nilSafetyPolicyID)}
	noRules := armfrontdoor.WebApplicationFirewallPolicy{
		ID:         toPtr(nilSafetyPolicyID),
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{},
	}

	for _, tc := range []struct {
		name             string
		existing, backup armfrontdoor.WebApplicationFirewallPolicy
		custom, managed  bool
	}{
		{"custom-only: backup has no rule list", fdPolicyForNilSafety(), noRules, true, false},
		{"custom-only: existing has no rule list", noRules, fdPolicyForNilSafety(), true, false},
		{"custom-only: backup has no properties", fdPolicyForNilSafety(), noProps, true, false},
		{"custom-only: existing has no properties", noProps, fdPolicyForNilSafety(), true, false},
		{"managed-only: backup has no properties", fdPolicyForNilSafety(), noProps, false, true},
		{"managed-only: existing has no properties", noProps, fdPolicyForNilSafety(), false, true},
		{"both: backup has no properties", fdPolicyForNilSafety(), noProps, false, false},
		{"both: existing has no properties", noProps, fdPolicyForNilSafety(), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := WrappedPolicy{PolicyID: nilSafetyPolicyID, Policy: tc.existing}
			backup := WrappedPolicy{PolicyID: nilSafetyPolicyID, Policy: tc.backup}

			require.NotPanics(t, func() {
				_, err := BuildRestoredPolicy(&existing, &backup, &RestorePoliciesInput{
					CustomRulesOnly:  tc.custom,
					ManagedRulesOnly: tc.managed,
				})
				require.NoError(t, err)
			})
		})
	}
}

// Restoring from a backup that holds no custom rules clears the target's,
// rather than leaving stale rules behind.
func TestBuildRestoredPolicyClearsRulesAbsentFromBackup(t *testing.T) {
	existing := WrappedPolicy{PolicyID: nilSafetyPolicyID, Policy: fdPolicyForNilSafety()}
	backup := WrappedPolicy{
		PolicyID: nilSafetyPolicyID,
		Policy: armfrontdoor.WebApplicationFirewallPolicy{
			ID:         toPtr(nilSafetyPolicyID),
			Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{},
		},
	}

	got, err := BuildRestoredPolicy(&existing, &backup, &RestorePoliciesInput{CustomRulesOnly: true})
	require.NoError(t, err)
	require.Empty(t, got.Policy.Properties.CustomRules.Rules)
}

// --- exclusion paths ---

// The exclusion helpers walk deeply nested API structures — rule sets hold
// group overrides, which hold rules, which hold exclusions — and dereferenced
// names and identifiers at every level without checking. 19 of these 26 cases
// panicked before the sweep.
func TestExclusionHelpersToleratePartialStructures(t *testing.T) {
	emptyRuleSet := &armfrontdoor.ManagedRuleSet{}
	partialRuleSet := &armfrontdoor.ManagedRuleSet{
		RuleGroupOverrides: []*armfrontdoor.ManagedRuleGroupOverride{
			{RuleGroupName: nil, Rules: []*armfrontdoor.ManagedRuleOverride{{RuleID: nil}}},
			nil,
		},
		Exclusions: []*armfrontdoor.ManagedRuleExclusion{{}, nil},
	}
	dcri := &DeleteManagedRuleExclusionInput{Scope: ScopeRuleSet, ExclusionRuleSelector: "x"}

	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{"getRuleGroupExclusionsFromRuleSet nil", func() { getRuleGroupExclusionsFromRuleSet("g", nil) }},
		{"getRuleGroupExclusionsFromRuleSet partial", func() { getRuleGroupExclusionsFromRuleSet("g", partialRuleSet) }},
		{"getAllExclusionsByRuleID nil", func() { getAllExclusionsByRuleID("1", nil) }},
		{"getAllExclusionsByRuleID partial", func() { getAllExclusionsByRuleID("1", partialRuleSet) }},
		{"getShadowsFromRuleSet nil", func() { getShadowsFromRuleSet(nil) }},
		{"getShadowsFromRuleSet partial", func() { getShadowsFromRuleSet(partialRuleSet) }},
		{"HasMatchingExclusions nils", func() { HasMatchingExclusions(nil, nil) }},
		{"getRuleSetStats nil", func() { getRuleSetStats(nil, nil) }},
		{"getRuleSetStats empty", func() {
			getRuleSetStats(emptyRuleSet, &armfrontdoor.ManagedRuleSetDefinition{})
		}},
		{"getRuleSetDefinitionMatchingRuleSetTypeVersion partial", func() {
			getRuleSetDefinitionMatchingRuleSetTypeVersion([]*armfrontdoor.ManagedRuleSetDefinition{{}, nil}, "t", "v")
		}},
		{"getMatchingRuleSet nil list", func() {
			getMatchingRuleSet(getMatchingRuleSetInput{RuleSetList: nil, RuleID: "1"})
		}},
		{"getMatchingRuleSet partial", func() {
			getMatchingRuleSet(getMatchingRuleSetInput{
				RuleSetList: &armfrontdoor.ManagedRuleSetList{
					ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{{}, nil, partialRuleSet},
				},
				RuleID: "1",
			})
		}},
		{"stripFromManagedRuleSet nil", func() { _, _ = stripFromManagedRuleSet(dcri, nil) }},
		{"stripFromManagedRuleSet partial", func() { _, _ = stripFromManagedRuleSet(dcri, partialRuleSet) }},
		{"stripMatchingMREs nil", func() { _, _ = stripMatchingMREs(dcri, nil) }},
		{"stripMatchingMREs partial", func() {
			_, _ = stripMatchingMREs(dcri, &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{{}, nil},
			})
		}},
		{"stripManagedRuleOverride nil", func() { stripManagedRuleOverride(dcri, nil) }},
		{"stripManagedRuleOverride no rule id", func() {
			stripManagedRuleOverride(dcri, &armfrontdoor.ManagedRuleOverride{})
		}},
		{"stripManagedRuleGroupOverride nil", func() { _, _ = stripManagedRuleGroupOverride(dcri, nil) }},
		{"stripManagedRuleGroupOverrideExclusions nil entries", func() {
			stripManagedRuleGroupOverrideExclusions(dcri, []*armfrontdoor.ManagedRuleExclusion{{}, nil})
		}},
		{"stripManagedRuleGroupOverrideRules nil entries", func() {
			stripManagedRuleGroupOverrideRules(dcri, []*armfrontdoor.ManagedRuleOverride{{}, nil})
		}},
		{"addToManagedRuleSet nil", func() {
			_ = addToManagedRuleSet(&AddManagedRuleExclusionInput{Scope: ScopeRuleSet}, nil)
		}},
		{"HasRuleSets nil", func() { _, _ = HasRuleSets(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, tc.fn)
		})
	}
}
