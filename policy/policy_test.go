package policy

import (
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/sirupsen/logrus"

	_ "github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	logrus.SetLevel(logrus.DebugLevel)

	exitVal := m.Run()

	os.Exit(exitVal)
}

func LoadManagedRulesetDefinitions() (defs []*armfrontdoor.ManagedRuleSetDefinition, err error) {
	// #nosec
	data, oerr := os.ReadFile("testdata/managed_ruleset_definitions.json")
	if oerr != nil {
		err = oerr

		return
	}

	oerr = json.Unmarshal(data, &defs)
	if oerr != nil {
		err = oerr
	}

	return
}

func TestIsRIDHash(t *testing.T) {
	require.False(t, IsRIDHash(""))
	// lower case only
	require.False(t, IsRIDHash("ABC1F23"))
	// a-f and 0-9 only
	require.False(t, IsRIDHash("abcd1fgh"))
	require.True(t, IsRIDHash("abcd1f23"))
}

func TestValidateSubscriptionID(t *testing.T) {
	require.Error(t, validateSubscriptionID(""))
	// first segment too short
	require.Error(t, validateSubscriptionID("a914e76-4921-4c19-b460-a2d36003525a"))
	// second segment too short and third too short
	require.Error(t, validateSubscriptionID("0a914e76-49214-c19-b460-a2d36003525a"))
	require.Nil(t, validateSubscriptionID("0a914e76-4921-4c19-b460-a2d36003525a"))
}

func TestMatchExistingPolicyByID(t *testing.T) {
	wp, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-Policy-one.json")
	require.NoError(t, err)

	targetPolicyID := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone"
	found, policy := MatchExistingPolicyByID(targetPolicyID, []WrappedPolicy{wp})
	require.True(t, found)
	require.NotNil(t, policy)
}

// TestGeneratePolicyPatch compares two Policies and checks that the differences match the operations:
func TestGeneratePolicyPatch(t *testing.T) {
	pOne, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-Policy-one.json")
	require.NoError(t, err)

	pTwo, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-Policy-two.json")
	require.NoError(t, err)

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: pOne,
		New:      pTwo.Policy,
	})

	require.NoError(t, err)
	require.Equal(t, 4, patch.TotalRuleDifferences)
	require.Equal(t, 3, patch.CustomRuleChanges)
	require.Equal(t, 2, patch.CustomRuleRemovals)
	require.Equal(t, 1, patch.ManagedRuleChanges)
	require.Equal(t, 0, patch.CustomRuleReplacements)
	require.Equal(t, 1, patch.ManagedRuleReplacements)
}

func TestIsValidExclusionRuleVariable(t *testing.T) {
	// case-sensitive matches
	require.True(t, IsValidExclusionRuleVariable("QueryStringArgNames", false))
	require.True(t, IsValidExclusionRuleVariable("RequestBodyJsonArgNames", false))
	require.True(t, IsValidExclusionRuleVariable("RequestBodyPostArgNames", false))
	require.True(t, IsValidExclusionRuleVariable("RequestCookieNames", false))
	require.True(t, IsValidExclusionRuleVariable("RequestHeaderNames", false))
	// invalid case-sensitive matches
	require.False(t, IsValidExclusionRuleVariable("RequestNookieNames", false))
	// valid case-sensitive matches
	require.True(t, IsValidExclusionRuleVariable("querystringArgNames", true))
	require.True(t, IsValidExclusionRuleVariable("requestBodyJsonArgNames", true))
	require.True(t, IsValidExclusionRuleVariable("requestBodyPostArgNames", true))
	require.True(t, IsValidExclusionRuleVariable("requestcookieNames", true))
	require.True(t, IsValidExclusionRuleVariable("requestheaderNames", true))
	// invalid case-sensitive matche
	require.False(t, IsValidExclusionRuleVariable("uerystringArgNames", true))
}

// func IsStringValidExclusionRuleOperator(s string, ci bool) bool {
// 	if ci {
// 		for x := range ValidRuleExclusionMatchOperators {
// 			if strings.EqualFold(s, ValidRuleExclusionMatchOperators[x]) {
// 				return true
// 			}
// 		}
//
// 		return false
// 	}
//
// 	for x := range ValidRuleExclusionMatchOperators {
// 		if s == ValidRuleExclusionMatchOperators[x] {
// 			return true
// 		}
// 	}
//
// 	return false
// }

//
// func TestIsValidExclusionRuleOperator(t *testing.T) {
// 	// case-sensitive matches
//
// 	require.True(t, Valid("Contains", false))
// 	require.True(t, IsStringValidExclusionRuleOperator("EndsWith", false))
// 	require.True(t, IsStringValidExclusionRuleOperator("Equals", false))
// 	require.True(t, IsStringValidExclusionRuleOperator("EqualsAny", false))
// 	require.True(t, IsStringValidExclusionRuleOperator("StartsWith", false))
// 	// invalid case-sensitive matches
// 	require.False(t, IsStringValidExclusionRuleOperator("tartsWith", false))
// 	// valid case-sensitive matches
// 	require.True(t, IsStringValidExclusionRuleOperator("contains", true))
// 	require.True(t, IsStringValidExclusionRuleOperator("endsWith", true))
// 	require.True(t, IsStringValidExclusionRuleOperator("equals", true))
// 	require.True(t, IsStringValidExclusionRuleOperator("equalsAny", true))
// 	require.True(t, IsStringValidExclusionRuleOperator("startsWith", true))
// 	// invalid case-sensitive matche
// 	require.False(t, IsStringValidExclusionRuleOperator("quals", true))
// }

func TestGetFunctionName(t *testing.T) {
	require.Equal(t, "policy.TestGetFunctionName", GetFunctionName())
}

// func TestConvertToResourceIDs(t *testing.T) {
// 	ConvertToResourceIDs()
// 	require.Equal(t, "policy.TestGetFunctionName", GetFunctionName())
// }
// func TestConvertToResourceIDs(t *testing.T) {
// 	ConvertToResourceIDs()
// 	require.Equal(t, "policy.TestGetFunctionName", GetFunctionName())
// }

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// generateIPNets takes a CIDR and produces a list of IPNets within that range
func generateIPNets(cidr string) (ipns IPNets) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
	}

	for ip = ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ipstring := ip.String() + "/32"

		var ipn netip.Prefix
		ipn, err = netip.ParsePrefix(ipstring)

		if err != nil {
			log.Fatal(err)
		}

		ipns = append(ipns, ipn)
	}

	if len(ipns) > 0 {
		ipns = ipns[1 : len(ipns)-1]
	}

	sort.Slice(ipns, func(i, j int) bool {
		return ipns[i].String() < ipns[j].String()
	})

	return
}

func TestGenerateCustomRulesFromIPNets(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/18")

	require.Len(t, ipns, 16382)

	crs, err := GenCustomRulesFromIPNets(ipns, 90, "Block", "", 0)
	require.NoError(t, err)
	require.Len(t, crs, 28)

	for x := range crs {
		matchConditions := crs[x].MatchConditions

		mc := matchConditions[0]
		for y, mv := range mc.MatchValue {
			require.Equal(t, ipns[x*MaxIPMatchValues+y].String(), *mv)
		}
	}
}

func TestGenerateCustomRulesFromIPNets2(t *testing.T) {
	var ipns []netip.Prefix
	ipns = append(ipns, netip.MustParsePrefix("67.43.236.18/32"))
	ipns = append(ipns, netip.MustParsePrefix("67.43.236.20/31"))
	ipns = append(ipns, netip.MustParsePrefix("67.43.236.22/32"))

	crs, err := GenCustomRulesFromIPNets(ipns, 90, "Block", "", 0)
	require.NoError(t, err)
	require.Len(t, crs, 1)

	for x := range crs {
		matchConditions := crs[x].MatchConditions

		mc := matchConditions[0]
		for y, mv := range mc.MatchValue {
			require.Equal(t, ipns[x*MaxIPMatchValues+y].String(), *mv)
		}
	}
}

func TestGenerateCustomRulesFromIPNets3(t *testing.T) {
	var ipns []netip.Prefix
	ipns = append(ipns, netip.MustParsePrefix("67.43.236.18/32"))
	ipns = append(ipns, netip.MustParsePrefix("67.43.236.20/31"))
	ipns = append(ipns, netip.MustParsePrefix("67.43.236.22/32"))

	crs, err := GenCustomRulesFromIPNets(ipns, 90, "Block", "", 0)
	require.NoError(t, err)
	require.Len(t, crs, 1)

	for x := range crs {
		matchConditions := crs[x].MatchConditions

		mc := matchConditions[0]
		for y, mv := range mc.MatchValue {
			require.Equal(t, ipns[x*MaxIPMatchValues+y].String(), *mv)
		}
	}

	var ipns2 []netip.Prefix
	ipns2 = append(ipns2, netip.MustParsePrefix("67.43.236.18/32"))
	ipns2 = append(ipns2, netip.MustParsePrefix("67.43.236.22/32"))
	ipns2 = append(ipns2, netip.MustParsePrefix("67.43.236.20/31"))

	crs2, err := GenCustomRulesFromIPNets(ipns2, 90, "Block", "", 0)
	require.NoError(t, err)
	require.Len(t, crs2, 1)

	require.Equal(t, crs[0].MatchConditions[0].MatchValue[0], crs2[0].MatchConditions[0].MatchValue[0])
	require.Equal(t, crs[0].MatchConditions[0].MatchValue[1], crs2[0].MatchConditions[0].MatchValue[1])
	require.Equal(t, crs[0].MatchConditions[0].MatchValue[2], crs2[0].MatchConditions[0].MatchValue[2])
}

// Require that setting a positive value for max rules limits the number of rules generated
func TestGenerateCustomRulesFromIPNetsLimitsToMaxRules(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/21")
	require.Len(t, ipns, 2046)

	crs, err := GenCustomRulesFromIPNets(ipns, 3, "Block", "", 0)
	require.NoError(t, err)

	require.Len(t, crs, 3)
}

// Require that setting a zero value for max rules does not limit the number of rules generated
func TestGenerateCustomRulesFromIPNetsLimitsNotLimitedWhenMaxRulesZero(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/21")
	require.Len(t, ipns, 2046)

	crs, err := GenCustomRulesFromIPNets(ipns, 0, "Block", "", 0)

	require.NoError(t, err)
	require.Len(t, crs, 4)
}

// Require error if action not recognised
func TestGenerateCustomRulesFromIPNetsWithInvalidAction(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/21")

	require.Len(t, ipns, 2046)
	_, err := GenCustomRulesFromIPNets(ipns, 0, "Blocker", "", 0)
	require.Error(t, err)
}
