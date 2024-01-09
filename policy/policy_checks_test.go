package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasRuleSets(t *testing.T) {
	p, err := LoadPolicyFromFile("testdata/test-policy-one.json")
	require.NoError(t, err)

	ok, noRuleSets := HasRuleSets(&p)
	require.True(t, ok)
	require.Equal(t, 2, noRuleSets)

	p.Properties.ManagedRules.ManagedRuleSets = nil
	ok, noRuleSets = HasRuleSets(&p)
	require.False(t, ok)
	require.Equal(t, 0, noRuleSets)
}

func TestHasCustomRulesUndefined(t *testing.T) {
	ok, noRuleSets := HasCustomRules(nil)
	require.False(t, ok)
	require.Equal(t, 0, noRuleSets)
}

func TestHasCustomRulesTwo(t *testing.T) {
	p, err := LoadPolicyFromFile("testdata/test-policy-one.json")

	require.NoError(t, err)
	ok, noRuleSets := HasCustomRules(&p)
	require.True(t, ok)
	require.Equal(t, 2, noRuleSets)
}

func TestHasCustomRulesNone(t *testing.T) {
	p, err := LoadPolicyFromFile("testdata/test-policy-four.json")

	require.NoError(t, err)
	ok, noRuleSets := HasCustomRules(&p)
	require.False(t, ok)
	require.Equal(t, 0, noRuleSets)
}
