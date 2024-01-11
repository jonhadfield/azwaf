package policy

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
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
						RuleSetType:    to.Ptr("type1"),
						RuleSetVersion: to.Ptr("version1"),
					},
					{
						RuleSetType:    to.Ptr("type2"),
						RuleSetVersion: to.Ptr("version2"),
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
						RuleSetType:    to.Ptr("type1"),
						RuleSetVersion: to.Ptr("version1"),
					},
					{
						RuleSetType:    to.Ptr("type2"),
						RuleSetVersion: to.Ptr("version2"),
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
						RuleSetType:    to.Ptr("type1"),
						RuleSetVersion: to.Ptr("version1"),
					},
					{
						RuleSetType:    to.Ptr("type2"),
						RuleSetVersion: to.Ptr("version2"),
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
						RuleSetType:    to.Ptr("type2"),
						RuleSetVersion: to.Ptr("version2"),
					},
					{
						RuleSetType:    to.Ptr("type1"),
						RuleSetVersion: to.Ptr("version1"),
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
						RuleSetType:    to.Ptr("type1"),
						RuleSetVersion: to.Ptr("version1"),
					},
					{
						RuleSetType:    to.Ptr("type2"),
						RuleSetVersion: to.Ptr("version2"),
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
						RuleSetType:    to.Ptr("type3"),
						RuleSetVersion: to.Ptr("version3"),
					},
					{
						RuleSetType:    to.Ptr("type4"),
						RuleSetVersion: to.Ptr("version4"),
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
						RuleSetType:    to.Ptr("type1"),
						RuleSetVersion: to.Ptr("version1"),
					},
					{
						RuleSetType:    to.Ptr("type2"),
						RuleSetVersion: to.Ptr("version2"),
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
						RuleSetType:    to.Ptr("type1"),
						RuleSetVersion: to.Ptr("version1"),
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
