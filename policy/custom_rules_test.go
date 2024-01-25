package policy

import (
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/config"
	"github.com/stretchr/testify/require"
)

func TestIsRulePrefixNameValid(t *testing.T) {
	require.Nil(t, RuleNamePrefix("Test").Check())
	require.Error(t, RuleNamePrefix("").Check())
	require.Error(t, RuleNamePrefix("1Test").Check())
	require.Error(t, RuleNamePrefix("Test1").Check())
	require.Error(t, RuleNamePrefix("Tes t").Check())
}

func TestNormalisePrefixes(t *testing.T) {
	// test shortest of two that cleanly overlap is returned
	p1 := netip.MustParsePrefix("10.0.0.0/24")
	p2 := netip.MustParsePrefix("10.0.0.0/25")
	netPrefixes := IPNets{p1, p2}
	netPrefixes, err := Normalise(netPrefixes)
	require.NoError(t, err)
	require.Equal(t, 1, len(netPrefixes))
	require.Equal(t, netPrefixes[0], p1)

	// test shortest of three prefixes that overlap is returned
	p1 = netip.MustParsePrefix("10.1.0.0/24")
	p2 = netip.MustParsePrefix("10.1.0.0/16")
	p3 := netip.MustParsePrefix("10.1.1.0/25")
	netPrefixes, err = Normalise(IPNets{p1, p2, p3})
	require.NoError(t, err)
	require.Equal(t, 1, len(netPrefixes))
	require.Equal(t, netPrefixes[0], p2)

	// test multiple non-overlapping prefixes are returned
	p1 = netip.MustParsePrefix("10.2.0.0/16")
	p2 = netip.MustParsePrefix("10.1.0.0/16")
	netPrefixes, err = Normalise(IPNets{p1, p2})
	require.NoError(t, err)
	require.Equal(t, 2, len(netPrefixes))
	require.Equal(t, netPrefixes[1], p1)
	require.Equal(t, netPrefixes[0], p2)
}

func TestTryNetStrToPrefix(t *testing.T) {
	p, err := tryNetStrToPrefix("1.1.1.1")
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1/32", p.String())
	p, err = tryNetStrToPrefix("123.123.123.123/32")
	require.NoError(t, err)
	require.Equal(t, "123.123.123.123/32", p.String())
	p, err = tryNetStrToPrefix("0.0.0.0/0")
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0/0", p.String())
	p, err = tryNetStrToPrefix("1.2.3.256/32")
	require.Error(t, err)
	p, err = tryNetStrToPrefix("0.63.63.3.3/32")
	require.Error(t, err)
}

func TestGetNetsToRemove(t *testing.T) {
	out, err := getNetsToRemove("", IPNets{})
	require.Error(t, err)
	require.Nil(t, out)

	out, err = getNetsToRemove("", IPNets{netip.MustParsePrefix("1.1.1.1/32")})
	require.NoError(t, err)
	require.Len(t, out, 1)

	out, err = getNetsToRemove("", IPNets{netip.MustParsePrefix("1.1.1.1/32")})
	require.NoError(t, err)
	require.Len(t, out, 1)
}

// TestUpdatePolicyCustomRules
func TestUpdatePolicyCustomRules(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-one.json"})
	require.NoError(t, err)

	orig, err := CopyPolicy(wp[0].Policy)
	require.NoError(t, err)

	modified, _, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		BaseCLIInput:   BaseCLIInput{},
		Policy:         &wp[0].Policy,
		Action:         actionBlock,
		Filepath:       "",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("45.45.45.0/24")},
		RuleNamePrefix: "MyTest",
		PriorityStart:  6000,
		MaxRules:       100,
		LogLevel:       nil,
	})

	require.NoError(t, err)
	require.Greater(t, len(wp[0].Policy.Properties.CustomRules.Rules), len(orig.Properties.CustomRules.Rules))
	require.True(t, modified)
}

// TestUpdatePolicyCustomRulesExisting - update custom rules by passing a prefix that already exists should return no change
func TestUpdatePolicyCustomRulesExisting(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-three.json"})
	require.NoError(t, err)

	rid := config.ParseResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone")

	modified, patch, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		Policy:         &wp[0].Policy,
		SubscriptionID: rid.SubscriptionID,
		RawResourceID:  rid.Raw,
		Action:         actionBlock,
		Output:         false,
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22")},
		RuleNamePrefix: "BlockList",
		PriorityStart:  1,
		MaxRules:       2,
		LogLevel:       nil,
	})
	require.NoError(t, err)
	require.Equal(t, 0, patch.CustomRuleChanges)
	require.False(t, modified)
}

// TestUpdatePolicyCustomRulesNew - update custom rules by passing a prefix that doesn't exist should return a change
func TestUpdatePolicyCustomRulesNew(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-three.json"})
	require.NoError(t, err)

	rid := config.ParseResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone")

	modified, patch, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		Policy:         &wp[0].Policy,
		SubscriptionID: rid.SubscriptionID,
		RawResourceID:  rid.Raw,
		Action:         actionBlock,
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("9.9.9.9/32")},
		RuleNamePrefix: "BlockList",
		PriorityStart:  1,
		MaxRules:       2,
		LogLevel:       nil,
	})
	require.NoError(t, err)
	require.True(t, modified)
	require.Equal(t, 1, patch.CustomRuleAdditions)
}

// TestUpdatePolicyCustomRulesNew - update custom rules by passing two existing prefixes, but with a new prefix also, should return change
func TestUpdatePolicyCustomRulesNewNamePrefix(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-three.json"})
	require.NoError(t, err)

	rid := config.ParseResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone")

	modified, patch, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		BaseCLIInput:   BaseCLIInput{},
		Policy:         &wp[0].Policy,
		SubscriptionID: rid.SubscriptionID,
		RawResourceID:  rid.Raw,
		ResourceID:     config.ResourceID{},
		Action:         actionBlock,
		Output:         false,

		Filepath:       "",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "BlockListNew",
		PriorityStart:  1,
		MaxRules:       2,
		LogLevel:       nil,
	})
	require.NoError(t, err)
	require.Equal(t, 1, patch.CustomRuleAdditions)
	require.Equal(t, 1, patch.CustomRuleChanges)
	require.True(t, modified)
}

// TestUpdatePolicyCustomRulesNew - update custom rules by passing two existing prefixes, but with a new prefix also, should return change
func TestUpdatePolicyCustomRulesNewNamePrefixFromFile(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-three.json"})
	require.NoError(t, err)

	rid := config.ParseResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone")

	modified, patch, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		Policy:         &wp[0].Policy,
		SubscriptionID: rid.SubscriptionID,
		RawResourceID:  rid.Raw,
		ResourceID:     config.ResourceID{},
		Action:         actionBlock,
		Output:         false,
		Filepath:       "testdata/nets.txt",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "BlockListNew",
		PriorityStart:  1,
		MaxRules:       2,
		LogLevel:       nil,
	})
	require.NoError(t, err)
	require.Equal(t, 1, patch.CustomRuleAdditions)
	require.Equal(t, 1, patch.CustomRuleChanges)
	require.True(t, modified)

	modified, _, err = UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		BaseCLIInput:   BaseCLIInput{},
		Policy:         &wp[0].Policy,
		SubscriptionID: rid.SubscriptionID,
		RawResourceID:  rid.Raw,
		Action:         actionBlock,
		Filepath:       "testdata/nets.txt",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "BlockListNew",
		PriorityStart:  1,
		MaxRules:       2,
		LogLevel:       nil,
	})
	require.NoError(t, err)
	require.Equal(t, 1, patch.CustomRuleAdditions)
	require.Equal(t, 1, patch.CustomRuleChanges)
	require.False(t, modified)
}

// TestUpdatePolicyCustomRulesNegativeMatches
func TestUpdatePolicyCustomRulesAddNegativeMatches(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-three.json"})
	require.NoError(t, err)

	rid := config.ParseResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone")

	// check that adding exclusions triggers change
	modified, patch, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		BaseCLIInput:   BaseCLIInput{},
		Policy:         &wp[0].Policy,
		SubscriptionID: rid.SubscriptionID,
		RawResourceID:  rid.Raw,
		Action:         actionBlock,
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		ExcludedAddrs:  []netip.Prefix{netip.MustParsePrefix("2.2.0.0/22")},
		RuleNamePrefix: "BlockList",
		PriorityStart:  1,
		MaxRules:       2,
	})
	require.NoError(t, err)
	require.Equal(t, 1, patch.CustomRuleAdditions)
	require.Equal(t, 1, patch.CustomRuleChanges)
	require.True(t, modified)
}

// TestUpdatePolicyCustomRulesNegativeMatches
func TestUpdatePolicyCustomRulesRemoveNegativeMatches(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-four.json"})
	require.NoError(t, err)

	rid := config.ParseResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone")

	// check that adding exclusions triggers change
	modified, patch, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		BaseCLIInput:   BaseCLIInput{},
		Policy:         &wp[0].Policy,
		SubscriptionID: rid.SubscriptionID,
		RawResourceID:  rid.Raw,
		Action:         actionBlock,
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		ExcludedAddrs:  []netip.Prefix{netip.MustParsePrefix("2.2.0.0/22")},
		RuleNamePrefix: "BlockList",
		PriorityStart:  1,
		MaxRules:       2,
	})
	require.NoError(t, err)
	require.Equal(t, 1, patch.CustomRuleAdditions)
	require.Equal(t, 1, patch.CustomRuleChanges)
	require.True(t, modified)
}

// TestUpdatePolicyCustomRulesInvalidInput tests we get an error with nil input
func TestUpdatePolicyCustomRulesInvalidInput(t *testing.T) {
	_, _, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{})
	require.Error(t, err)
}

// TestUpdatePolicyCustomRulesInvalidInput tests we get an error with an invalid rule name prefix
func TestUpdatePolicyCustomRulesInvalidRuleNamePrefix(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-one.json"})
	require.NoError(t, err)
	_, _, err = UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		Policy:         &wp[0].Policy,
		Action:         "Block",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "Test One",
		PriorityStart:  0,
		MaxRules:       100,
		LogLevel:       nil,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "white space")
}

// TestUpdatePolicyCustomRulesInvalidInput tests we get an error with an invalid rule name prefix
func TestUpdatePolicyCustomRulesMissingPolicy(t *testing.T) {
	_, _, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		Policy:         nil,
		Action:         "Block",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "Testing",
		PriorityStart:  0,
		MaxRules:       100,
		LogLevel:       nil,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "policy")
}

func TestGetLowestPriority(t *testing.T) {
	require.Equal(t, int32(500), getLowestPriority([]*armfrontdoor.CustomRule{
		{
			Priority: toPtr(int32(5)),
			Name:     toPtr("Hello"),
		},
		{
			Priority: toPtr(int32(1234)),
			Name:     toPtr("TestPrefix1234"),
		},
		{
			MatchConditions: nil,
			Priority:        toPtr(int32(500)),
			Name:            toPtr("TestPrefix500"),
		},
		{
			Priority: toPtr(int32(6000)),
			Name:     toPtr("TestPrefix6000"),
		},
	}, "TestPrefix"))
}

// Func customRuleWithDefaultDeny() armfrontdoor.CustomRule {
// 	ipnpi := ipMatchValuesNoPublicInternet()
// 	mc1 := armfrontdoor.MatchCondition{
// 		MatchVariable:   "RemoteAddr",
// 		Selector:        nil,
// 		Operator:        "IPMatch",
// 		NegateCondition: BoolToPointer(true),
// 		MatchValue:      &ipnpi,
// 		Transforms:      nil,
// 	}
//
// 	mcSet := []armfrontdoor.MatchCondition{mc1}
//
// 	return armfrontdoor.CustomRule{
// 		Name:            toPtr("CustomRuleWithDefaultDeny"),
// 		PriorityS:        Int32ToPointer(1),
// 		EnabledState:    "Enabled",
// 		RuleType:        "MatchRule",
// 		MatchConditions: &mcSet,
// 		Action:          "Block",
// 	}
// }
//
// func customRuleWithDefaultAllow() armfrontdoor.CustomRule {
// 	ipnpi := ipMatchValuesNoPublicInternet()
// 	ipwpi := ipMatchValuesWithPublicInternet()
// 	mc1 := armfrontdoor.MatchCondition{
// 		MatchVariable:   "RemoteAddr",
// 		Selector:        nil,
// 		Operator:        "IPMatch",
// 		NegateCondition: BoolToPointer(true),
// 		MatchValue:      &ipnpi,
// 		Transforms:      nil,
// 	}
// 	mc2 := armfrontdoor.MatchCondition{
// 		MatchVariable:   "RemoteAddr",
// 		Selector:        nil,
// 		Operator:        "IPMatch",
// 		NegateCondition: BoolToPointer(false),
// 		MatchValue:      &ipwpi,
// 		Transforms:      nil,
// 	}
//
// 	mcSet := []armfrontdoor.MatchCondition{mc1, mc2}
//
// 	return armfrontdoor.CustomRule{
// 		Name:            toPtr("CustomRuleWithDefaultDeny"),
// 		PriorityS:        Int32ToPointer(1),
// 		EnabledState:    "Enabled",
// 		RuleType:        "MatchRule",
// 		MatchConditions: &mcSet,
// 		Action:          "Allow",
// 	}
// }

//
// Func customRuleWithoutDefaultDeny() armfrontdoor.CustomRule {
//	ipnpi := ipMatchValuesNoPublicInternet()
//	ipwpi := ipMatchValuesWithPublicInternet()
//	mc1 := armfrontdoor.MatchCondition{
//		MatchVariable:   "RemoteAddr",
//		Selector:        nil,
//		Operator:        "IPMatch",
//		NegateCondition: BoolToPointer(true),
//		MatchValue:      &ipnpi,
//		Transforms:      nil,
//	}
//	mc2 := armfrontdoor.MatchCondition{
//		MatchVariable:   "RemoteAddr",
//		Selector:        nil,
//		Operator:        "IPMatch",
//		NegateCondition: BoolToPointer(false),
//		MatchValue:      &ipwpi,
//		Transforms:      nil,
//	}
//
//	mcSet := []armfrontdoor.MatchCondition{mc1, mc2}
//	return armfrontdoor.CustomRule{
//		Name:            toPtr("CustomRuleWithDefaultDeny"),
//		PriorityS:        Int32ToPointer(1),
//		EnabledState:    "Enabled",
//		RuleType:        "MatchRule",
//		MatchConditions: &mcSet,
//		Action:          "Block",
//	}
// }

func TestMatchConditionSupportedNegatedCondition(t *testing.T) {
	mc := &armfrontdoor.MatchCondition{
		MatchVariable:   toPtr(armfrontdoor.MatchVariableRemoteAddr),
		Operator:        toPtr(armfrontdoor.OperatorIPMatch),
		NegateCondition: toPtr(true),
	}

	assert.True(t, matchConditionSupported(mc))
}

func TestMatchConditionValidForUnblockInvalidMatchVariable(t *testing.T) {
	mc := &armfrontdoor.MatchCondition{
		MatchVariable:   toPtr(armfrontdoor.MatchVariableRequestMethod),
		Operator:        toPtr(armfrontdoor.OperatorIPMatch),
		NegateCondition: toPtr(false),
	}

	assert.False(t, matchConditionSupported(mc))
}

func TestMatchConditionValidForUnblockInvalidOperator(t *testing.T) {
	mc := &armfrontdoor.MatchCondition{
		NegateCondition: toPtr(false),
		MatchVariable:   toPtr(armfrontdoor.MatchVariableRemoteAddr),
		Operator:        toPtr(armfrontdoor.OperatorContains),
	}
	assert.False(t, matchConditionSupported(mc))
}

func TestMatchConditionValidForUnblockValidCondition(t *testing.T) {
	mc := &armfrontdoor.MatchCondition{
		NegateCondition: toPtr(false),
		MatchVariable:   toPtr(armfrontdoor.MatchVariableRemoteAddr),
		Operator:        toPtr(armfrontdoor.OperatorIPMatch),
	}
	assert.True(t, matchConditionSupported(mc))
}
