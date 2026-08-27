package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/stretchr/testify/require"
)

// The accessors exist to stop optional-pointer chains being walked by hand.
// That only holds if new code uses them, and convention alone has not held in
// this package before — valueOrDash was itself unsafe. Fail on any read of a
// Properties.CustomRules / Properties.ManagedRules chain outside accessors.go.
//
// Writes are exempt: assigning through the chain is how a policy is updated,
// and an accessor cannot express that. Those sites establish the container
// themselves, immediately above the assignment.
func TestPropertyChainsGoThroughAccessors(t *testing.T) {
	var offenders []string

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()

	for _, e := range entries {
		name := e.Name()
		// appgw_restore.go models Application Gateway policies, a different SDK
		// type tree that these accessors do not cover. It was checked
		// separately and is already nil-safe.
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") ||
			name == "accessors.go" || name == "appgw_restore.go" {
			continue
		}

		file, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, perr)

		// collect assignment targets, including the selectors nested inside
		// them, so `x.Properties.CustomRules.Rules = ...` is exempt in full
		written := map[ast.Node]bool{}

		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}

			for _, lhs := range assign.Lhs {
				ast.Inspect(lhs, func(inner ast.Node) bool {
					written[inner] = true

					return true
				})
			}

			return true
		})

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || written[n] {
				return true
			}

			// match X.Properties.<CustomRules|ManagedRules>
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok || inner.Sel.Name != "Properties" {
				return true
			}

			if sel.Sel.Name == "CustomRules" || sel.Sel.Name == "ManagedRules" {
				offenders = append(offenders, fset.Position(sel.Pos()).String())
			}

			return true
		})
	}

	require.Empty(t, offenders,
		"read Front Door policy rules through the accessors in accessors.go, not by walking "+
			"Properties by hand; found at %v", offenders)
}

// The accessors' whole purpose: every one returns empty rather than panicking
// when a level is absent.
func TestAccessorsReturnEmptyForAbsentLevels(t *testing.T) {
	empty := &armfrontdoor.WebApplicationFirewallPolicy{}
	noRules := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{},
	}

	require.NotPanics(t, func() {
		for _, p := range []*armfrontdoor.WebApplicationFirewallPolicy{nil, empty, noRules} {
			require.Empty(t, policyCustomRules(p))
			require.Nil(t, policyCustomRuleList(p))
			require.Empty(t, policyManagedRuleSets(p))
			require.Nil(t, policyManagedRuleSetList(p))
		}

		require.Empty(t, ruleSetListSets(nil))
		require.Empty(t, ruleSetGroupOverrides(nil))
		require.Empty(t, ruleSetExclusions(nil))
		require.Empty(t, groupOverrideRules(nil))
		require.Empty(t, groupOverrideExclusions(nil))
		require.Empty(t, ruleOverrideExclusions(nil))
		require.Empty(t, derefOrEmpty(nil))
	})
}

// And they return the real values when the levels are present.
func TestAccessorsReturnPopulatedValues(t *testing.T) {
	rule := &armfrontdoor.CustomRule{Name: toPtr("R")}
	exclusion := &armfrontdoor.ManagedRuleExclusion{Selector: toPtr("s")}
	override := &armfrontdoor.ManagedRuleOverride{RuleID: toPtr("1"), Exclusions: []*armfrontdoor.ManagedRuleExclusion{exclusion}}
	group := &armfrontdoor.ManagedRuleGroupOverride{
		RuleGroupName: toPtr("G"),
		Rules:         []*armfrontdoor.ManagedRuleOverride{override},
		Exclusions:    []*armfrontdoor.ManagedRuleExclusion{exclusion},
	}
	ruleSet := &armfrontdoor.ManagedRuleSet{
		RuleGroupOverrides: []*armfrontdoor.ManagedRuleGroupOverride{group},
		Exclusions:         []*armfrontdoor.ManagedRuleExclusion{exclusion},
	}
	p := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			CustomRules:  &armfrontdoor.CustomRuleList{Rules: []*armfrontdoor.CustomRule{rule}},
			ManagedRules: &armfrontdoor.ManagedRuleSetList{ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{ruleSet}},
		},
	}

	require.Equal(t, []*armfrontdoor.CustomRule{rule}, policyCustomRules(p))
	require.Equal(t, []*armfrontdoor.ManagedRuleSet{ruleSet}, policyManagedRuleSets(p))
	require.Equal(t, []*armfrontdoor.ManagedRuleGroupOverride{group}, ruleSetGroupOverrides(ruleSet))
	require.Equal(t, []*armfrontdoor.ManagedRuleExclusion{exclusion}, ruleSetExclusions(ruleSet))
	require.Equal(t, []*armfrontdoor.ManagedRuleOverride{override}, groupOverrideRules(group))
	require.Equal(t, []*armfrontdoor.ManagedRuleExclusion{exclusion}, groupOverrideExclusions(group))
	require.Equal(t, []*armfrontdoor.ManagedRuleExclusion{exclusion}, ruleOverrideExclusions(override))
	require.Equal(t, "x", derefOrEmpty(toPtr("x")))
}
