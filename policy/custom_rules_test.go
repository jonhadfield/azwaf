package policy

import (
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/config"
	"github.com/stretchr/testify/require"
)

func TestGetRateLimitConfigMismatched(t *testing.T) {
	rule1 := &armfrontdoor.CustomRule{
		RateLimitDurationInMinutes: toPtr(int32(1)),
		RateLimitThreshold:         toPtr(int32(223)),
	}
	rule2 := &armfrontdoor.CustomRule{
		RateLimitDurationInMinutes: toPtr(int32(5)),
		RateLimitThreshold:         toPtr(int32(123)),
	}

	rules := []*armfrontdoor.CustomRule{rule1, rule2}
	_, _, err := getRateLimitConfig(rules)
	require.Error(t, err)
}

func TestGetRateLimitConfig(t *testing.T) {
	rule1 := &armfrontdoor.CustomRule{
		RuleType:                   toPtr(armfrontdoor.RuleTypeRateLimitRule),
		RateLimitDurationInMinutes: toPtr(int32(5)),
		RateLimitThreshold:         toPtr(int32(223)),
	}
	rule2 := &armfrontdoor.CustomRule{
		RuleType:                   toPtr(armfrontdoor.RuleTypeRateLimitRule),
		RateLimitDurationInMinutes: toPtr(int32(5)),
		RateLimitThreshold:         toPtr(int32(223)),
	}

	rules := []*armfrontdoor.CustomRule{rule1, rule2}
	threshold, duration, err := getRateLimitConfig(rules)
	require.NoError(t, err)
	require.NotNil(t, threshold)
	require.NotNil(t, duration)
	require.Equal(t, *threshold, int32(223))
	require.Equal(t, *duration, int32(5))
}

// TestUpdatePolicyCustomRulesNegativeMatches
func TestDecorateExistingCustomRules(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{"../testfiles/wrapped-policy-three.json"})
	require.NoError(t, err)

	rid := config.ParseResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone")

	// check that adding exclusions triggers change
	modified, patch, err := DecorateExistingCustomRule(DecorateExistingCustomRuleInput{
		Policy:                  &wp[0].Policy,
		SubscriptionID:          rid.SubscriptionID,
		RawResourceID:           rid.Raw,
		Action:                  toPtr(armfrontdoor.ActionTypeBlock),
		Output:                  true,
		AdditionalAddrs:         []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22"), netip.MustParsePrefix("6.6.0.0/22")},
		AdditionalExcludedAddrs: []netip.Prefix{netip.MustParsePrefix("2.2.0.0/22")},
		RuleType:                toPtr(armfrontdoor.RuleTypeMatchRule),
		RuleName:                "BlockList1",
		PriorityStart:           1,
		MaxRules:                2,
		LogLevel:                nil,
	})
	require.NoError(t, err)
	require.True(t, modified)

	require.Equal(t, 2, patch.CustomRuleAdditions)
	require.Equal(t, 3, patch.CustomRuleChanges)

	// check that existing rules unaffected
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[0].Name, "RuleOne")
	require.Equal(t, int32ptr(1), wp[0].Policy.Properties.CustomRules.Rules[0].RateLimitDurationInMinutes)
	require.Equal(t, int32ptr(100), wp[0].Policy.Properties.CustomRules.Rules[0].RateLimitThreshold)
	require.Len(t, wp[0].Policy.Properties.CustomRules.Rules[0].MatchConditions, 1)

	// check that decorated rule only changed by decoration
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[1].Name, "BlockList1")
	require.Nil(t, wp[0].Policy.Properties.CustomRules.Rules[1].RateLimitDurationInMinutes)
	require.Nil(t, wp[0].Policy.Properties.CustomRules.Rules[1].RateLimitThreshold)
	require.Len(t, wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions, 2)
	// check positive matches
	require.Len(t, wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[0].MatchValue, 5)
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[0].MatchValue[0], "1.1.0.0/22")
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[0].MatchValue[1], "3.3.0.0/22")
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[0].MatchValue[2], "5.5.0.0/22")
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[0].MatchValue[3], "6.6.0.0/22")
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[0].MatchValue[4], "7.4.0.0/24")
	// check negative match
	require.Len(t, wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[1].MatchValue, 1)
	require.Equal(t, *wp[0].Policy.Properties.CustomRules.Rules[1].MatchConditions[1].MatchValue[0], "2.2.0.0/22")
	require.True(t, modified)
}

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
		Action:         toPtr(armfrontdoor.ActionTypeBlock),
		Filepath:       "",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("45.45.45.0/24")},
		RuleNamePrefix: "MyTest",
		RuleType:       toPtr(armfrontdoor.RuleTypeMatchRule),
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
		Policy:                     &wp[0].Policy,
		SubscriptionID:             rid.SubscriptionID,
		RawResourceID:              rid.Raw,
		ResourceID:                 config.ResourceID{},
		Action:                     toPtr(armfrontdoor.ActionTypeBlock),
		Output:                     false,
		Addrs:                      []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22")},
		ExcludedAddrs:              nil,
		RuleNamePrefix:             "BlockList",
		RuleType:                   toPtr(armfrontdoor.RuleTypeMatchRule),
		RateLimitDurationInMinutes: nil,
		RateLimitThreshold:         nil,
		PriorityStart:              1,
		MaxRules:                   2,
		LogLevel:                   nil,
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
		Action:         toPtr(armfrontdoor.ActionTypeBlock),
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("9.9.9.9/32")},
		RuleNamePrefix: "BlockList",
		RuleType:       toPtr(armfrontdoor.RuleTypeMatchRule),
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
		RuleType:       toPtr(armfrontdoor.RuleTypeMatchRule),
		ResourceID:     config.ResourceID{},
		Action:         toPtr(armfrontdoor.ActionTypeBlock),
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
		Action:         toPtr(armfrontdoor.ActionTypeBlock),
		Output:         false,
		Filepath:       "testdata/nets.txt",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "BlockListNew",
		RuleType:       toPtr(armfrontdoor.RuleTypeMatchRule),
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
		Action:         toPtr(armfrontdoor.ActionTypeBlock),
		Filepath:       "testdata/nets.txt",
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "BlockListNew",
		RuleType:       toPtr(armfrontdoor.RuleTypeMatchRule),
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
		BaseCLIInput:               BaseCLIInput{},
		Policy:                     &wp[0].Policy,
		SubscriptionID:             rid.SubscriptionID,
		RawResourceID:              rid.Raw,
		Action:                     toPtr(armfrontdoor.ActionTypeBlock),
		Output:                     true,
		Addrs:                      []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		ExcludedAddrs:              []netip.Prefix{netip.MustParsePrefix("2.2.0.0/22")},
		RuleNamePrefix:             "BlockList",
		RuleType:                   toPtr(armfrontdoor.RuleTypeMatchRule),
		RateLimitDurationInMinutes: nil,
		RateLimitThreshold:         nil,
		PriorityStart:              1,
		MaxRules:                   2,
		LogLevel:                   nil,
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
		BaseCLIInput:               BaseCLIInput{},
		Policy:                     &wp[0].Policy,
		SubscriptionID:             rid.SubscriptionID,
		RawResourceID:              rid.Raw,
		ResourceID:                 config.ResourceID{},
		Action:                     toPtr(armfrontdoor.ActionTypeBlock),
		Output:                     false,
		Addrs:                      []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		ExcludedAddrs:              []netip.Prefix{netip.MustParsePrefix("2.2.0.0/22")},
		RuleNamePrefix:             "BlockList",
		RuleType:                   toPtr(armfrontdoor.RuleTypeMatchRule),
		RateLimitDurationInMinutes: nil,
		RateLimitThreshold:         nil,
		PriorityStart:              1,
		MaxRules:                   2,
		LogLevel:                   nil,
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
		Action:         toPtr(armfrontdoor.ActionTypeBlock),
		Addrs:          []netip.Prefix{netip.MustParsePrefix("1.1.0.0/22"), netip.MustParsePrefix("3.3.0.0/22")},
		RuleNamePrefix: "Test One",
		PriorityStart:  0,
		MaxRules:       100,
		LogLevel:       nil,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "white space")
}

func TestSortCustomRulesByPriority(t *testing.T) {
	rules := []*armfrontdoor.CustomRule{
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
	}

	sortCustomRulesByPriority(rules)
	assert.Equal(t, *rules[0].Priority, int32(5))
	assert.Equal(t, *rules[1].Priority, int32(500))
	assert.Equal(t, *rules[2].Priority, int32(1234))
	assert.Equal(t, *rules[3].Priority, int32(6000))
}

// TestUpdatePolicyCustomRulesInvalidInput tests we get an error with an invalid rule name prefix
func TestUpdatePolicyCustomRulesMissingPolicy(t *testing.T) {
	_, _, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
		Policy:         nil,
		Action:         toPtr(armfrontdoor.ActionTypeBlock),
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

func TestFilterCustomRulesWithNilInput(t *testing.T) {
	_, err := filterCustomRules(filterCustomRulesInput{})
	assert.Error(t, err)
}

func TestFilterCustomRulesWithEmptyCustomRules(t *testing.T) {
	customRules := []*armfrontdoor.CustomRule{}
	input := filterCustomRulesInput{
		customRules: customRules,
	}
	_, err := filterCustomRules(input)
	assert.NoError(t, err)
}

func TestFilterCustomRulesWithMatchingCriteria(t *testing.T) {
	action := armfrontdoor.ActionTypeBlock
	ruleType := armfrontdoor.RuleTypeMatchRule
	name := "TestRule"
	customRules := []*armfrontdoor.CustomRule{
		{
			Action:   &action,
			RuleType: &ruleType,
			Name:     &name,
		},
	}
	input := filterCustomRulesInput{
		customRules: customRules,
		action:      &action,
		ruleType:    &ruleType,
		namePrefix:  RuleNamePrefix("Test"),
	}
	filteredRules, err := filterCustomRules(input)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(filteredRules))
}

func TestFilterCustomRulesWithNonMatchingCriteria(t *testing.T) {
	action := armfrontdoor.ActionTypeBlock
	ruleType := armfrontdoor.RuleTypeMatchRule
	name := "TestRule"
	customRules := []*armfrontdoor.CustomRule{
		{
			Action:   &action,
			RuleType: &ruleType,
			Name:     &name,
		},
	}
	input := filterCustomRulesInput{
		customRules: customRules,
		action:      &action,
		ruleType:    &ruleType,
		namePrefix:  RuleNamePrefix("NonMatching"),
	}
	filteredRules, err := filterCustomRules(input)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(filteredRules))
}

func TestFilterCustomRulesWithMatchingName(t *testing.T) {
	action := armfrontdoor.ActionTypeBlock
	ruleType := armfrontdoor.RuleTypeMatchRule
	name := "TestRule"
	customRules := []*armfrontdoor.CustomRule{
		{
			Action:   &action,
			RuleType: &ruleType,
			Name:     &name,
		},
	}
	input := filterCustomRulesInput{
		customRules: customRules,
		action:      &action,
		ruleType:    &ruleType,
		names:       []string{"TestRule"},
	}
	filteredRules, err := filterCustomRules(input)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(filteredRules))
}

func TestFilterCustomRulesWithNonMatchingName(t *testing.T) {
	action := armfrontdoor.ActionTypeBlock
	ruleType := armfrontdoor.RuleTypeMatchRule
	name := "TestRule1"
	customRules := []*armfrontdoor.CustomRule{
		{
			Action:   &action,
			RuleType: &ruleType,
			Name:     &name,
		},
	}
	input := filterCustomRulesInput{
		customRules: customRules,
		action:      &action,
		ruleType:    &ruleType,
		names:       []string{"TestRule"},
	}
	filteredRules, err := filterCustomRules(input)
	require.NoError(t, err)
	require.NotEqual(t, 1, len(filteredRules))
}
