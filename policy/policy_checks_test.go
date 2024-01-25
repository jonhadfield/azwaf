package policy

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
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

func TestEqualRuleSetsHappyPath(t *testing.T) {
	one := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type1"),
						RuleSetVersion: toPtr("version1"),
					},
					{
						RuleSetType:    toPtr("type2"),
						RuleSetVersion: toPtr("version2"),
					},
				},
			},
		},
	}

	two := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type1"),
						RuleSetVersion: toPtr("version1"),
					},
					{
						RuleSetType:    toPtr("type2"),
						RuleSetVersion: toPtr("version2"),
					},
				},
			},
		},
	}

	require.True(t, HaveEqualRuleSets(one, two))
}

func TestEqualRuleSetsDifferentOrder(t *testing.T) {
	one := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type1"),
						RuleSetVersion: toPtr("version1"),
					},
					{
						RuleSetType:    toPtr("type2"),
						RuleSetVersion: toPtr("version2"),
					},
				},
			},
		},
	}

	two := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type2"),
						RuleSetVersion: toPtr("version2"),
					},
					{
						RuleSetType:    toPtr("type1"),
						RuleSetVersion: toPtr("version1"),
					},
				},
			},
		},
	}

	require.True(t, HaveEqualRuleSets(one, two))
}

func TestEqualRuleSetsDifferentTypes(t *testing.T) {
	one := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type1"),
						RuleSetVersion: toPtr("version1"),
					},
					{
						RuleSetType:    toPtr("type2"),
						RuleSetVersion: toPtr("version2"),
					},
				},
			},
		},
	}

	two := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type3"),
						RuleSetVersion: toPtr("version3"),
					},
					{
						RuleSetType:    toPtr("type4"),
						RuleSetVersion: toPtr("version4"),
					},
				},
			},
		},
	}

	require.False(t, HaveEqualRuleSets(one, two))
}

func TestEqualRuleSetsDifferentLengths(t *testing.T) {
	one := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type1"),
						RuleSetVersion: toPtr("version1"),
					},
					{
						RuleSetType:    toPtr("type2"),
						RuleSetVersion: toPtr("version2"),
					},
				},
			},
		},
	}

	two := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			ManagedRules: &armfrontdoor.ManagedRuleSetList{
				ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
					{
						RuleSetType:    toPtr("type1"),
						RuleSetVersion: toPtr("version1"),
					},
				},
			},
		},
	}

	require.False(t, HaveEqualRuleSets(one, two))
}

func TestEqualRuleSetsNilPolicies(t *testing.T) {
	require.False(t, HaveEqualRuleSets(nil, nil))
}
