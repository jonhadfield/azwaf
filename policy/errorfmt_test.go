package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"
	"github.com/stretchr/testify/require"
)

// getPolicyStats reaches an error path that used to be built as
// fmt.Errorf(fmt.Sprintf(...), funcName). The inner Sprintf consumed every
// verb, so funcName was a surplus argument and Go appended
// "%!(EXTRA string=...)" to what the user saw, while the call-site context the
// argument was meant to supply was lost.
func TestGetPolicyStatsErrorNamesItsCallerAndHasNoFormatNoise(t *testing.T) {
	policy := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("Microsoft_DefaultRuleSet"),
						RuleSetVersion: toPtr("2.1"),
					},
				},
			},
		},
	}

	// a definition list that does not cover the policy's rule set
	definitions := []*armfrontdoor.ManagedRuleSetDefinition{
		{
			Properties: &armfrontdoor.ManagedRuleSetDefinitionProperties{
				RuleSetType:    toPtr("Microsoft_BotManagerRuleSet"),
				RuleSetVersion: toPtr("1.0"),
			},
		},
	}

	_, err := getPolicyStats(policy, definitions)
	require.Error(t, err)

	require.NotContains(t, err.Error(), "%!", "error carries Go format-verb noise: %s", err)
	require.Contains(t, err.Error(), "failed to get matching definition for rule set Microsoft_DefaultRuleSet_2.1")
	require.Contains(t, err.Error(), "getPolicyStats", "error should name the function it came from")
}

// fmt.Errorf(fmt.Sprintf(...), args) is invisible to go vet, because the format
// string is not a constant it can analyse. Five of these reached users with
// "%!(EXTRA string=...)" appended. Guard the whole package against the shape
// coming back rather than the five individual sites.
func TestNoErrorfWrappingSprintf(t *testing.T) {
	var offenders []string

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}

		file, perr := parser.ParseFile(fset, e.Name(), nil, 0)
		require.NoError(t, perr)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isPkgCall(call, "fmt", "Errorf") || len(call.Args) == 0 {
				return true
			}

			// the offence is a Sprintf supplying the *format string* itself
			if inner, ok := call.Args[0].(*ast.CallExpr); ok && isPkgCall(inner, "fmt", "Sprintf") {
				offenders = append(offenders,
					filepath.Base(fset.Position(call.Pos()).Filename)+":"+
						strings.TrimPrefix(fset.Position(call.Pos()).String(), e.Name()+":"))
			}

			return true
		})
	}

	require.Empty(t, offenders,
		"fmt.Errorf must take a constant format string, not a Sprintf result; found at %v", offenders)
}

func isPkgCall(call *ast.CallExpr, pkg, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)

	return ok && ident.Name == pkg
}
