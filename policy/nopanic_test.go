package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/alexeyco/simpletable"
	"github.com/stretchr/testify/require"
)

// formatRuleEnabledState used to panic when handed a state it did not
// recognise together with an unusable default. PrintPolicyCustomRule passes
// "-" as the default (output.go:1049), so any unexpected state from the API
// took the whole process down mid-table.
func TestFormatRuleEnabledStateHandlesUnknownStates(t *testing.T) {
	require.NotPanics(t, func() {
		require.Equal(t, "-", formatRuleEnabledState("Sideways", "-"))
		require.Equal(t, "-", formatRuleEnabledState("", ""))
		require.Equal(t, "-", formatRuleEnabledState("Unknown", "AlsoUnknown"))
	})

	// recognised states still resolve, directly and via the default
	require.Contains(t, formatRuleEnabledState("Enabled", "-"), "Enabled")
	require.Contains(t, formatRuleEnabledState("Disabled", "-"), "Disabled")
	require.Contains(t, formatRuleEnabledState("Unknown", "Enabled"), "Enabled")
}

// A match condition with no NegateCondition used to panic while rendering.
func TestOutputCustomRuleMatchConditionsToleratesNilNegate(t *testing.T) {
	mv := armfrontdoor.MatchVariableRequestURI
	op := armfrontdoor.OperatorContains

	enabled := armfrontdoor.CustomRuleEnabledStateEnabled
	ruleType := armfrontdoor.RuleTypeMatchRule
	action := armfrontdoor.ActionTypeBlock

	rule := &armfrontdoor.CustomRule{
		Name:         toPtr("NoNegate"),
		Priority:     toPtr(int32(100)),
		EnabledState: &enabled,
		RuleType:     &ruleType,
		Action:       &action,
		MatchConditions: []*armfrontdoor.MatchCondition{
			{
				MatchVariable:   &mv,
				Operator:        &op,
				MatchValue:      []*string{toPtr("/admin")},
				NegateCondition: nil,
			},
		},
	}

	require.NotPanics(t, func() {
		appendCustomRuleRows(simpletable.New(), rule, false)
	})
}

// The precondition that used to panic is now reported as an error.
func TestGetMatchingDefaultDefinitionsRequiresRuleSetDetails(t *testing.T) {
	defs, err := LoadManagedRulesetDefinitions()
	require.NoError(t, err)

	for _, tc := range []struct{ name, rsType, rsVersion string }{
		{"no type", "", "1.1"},
		{"no version", "Microsoft_DefaultRuleSet", ""},
		{"neither", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, derr := getMatchingDefaultDefinitions(&getMatchingDefaultDefinitionsInput{
					mrsdl:          defs,
					ruleID:         "944250",
					ruleSetType:    tc.rsType,
					ruleSetVersion: tc.rsVersion,
				})
				require.ErrorContains(t, derr, "rule set type and version are required")
			})
		})
	}
}

// Guard the package against panics returning to non-test code.
func TestNoPanicsInPolicyPackage(t *testing.T) {
	var offenders []string

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}

		file, perr := parser.ParseFile(fset, e.Name(), nil, 0)
		require.NoError(t, perr)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "panic" {
				offenders = append(offenders, fset.Position(call.Pos()).String())
			}

			return true
		})
	}

	require.Empty(t, offenders,
		"library code must return errors rather than panic; found panic at %v", offenders)
}
