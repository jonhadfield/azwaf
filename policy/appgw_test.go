package policy

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/jonhadfield/azwaf/config"
	"github.com/stretchr/testify/require"
)

func newAppGWPolicyForTest() armnetwork.WebApplicationFirewallPolicy {
	owasp := "OWASP"
	v32 := "3.2"
	return armnetwork.WebApplicationFirewallPolicy{
		Properties: &armnetwork.WebApplicationFirewallPolicyPropertiesFormat{
			ManagedRules: &armnetwork.ManagedRulesDefinition{
				ManagedRuleSets: []*armnetwork.ManagedRuleSet{
					{RuleSetType: &owasp, RuleSetVersion: &v32},
				},
			},
		},
	}
}

func TestWAFTypeFromResourceID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "frontdoor lowercase",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/p1",
			want: WAFTypeFrontDoor,
		},
		{
			name: "appgw mixed case",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/p2",
			want: WAFTypeAppGW,
		},
		{
			name: "appgw lower case",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/applicationgatewaywebapplicationfirewallpolicies/p3",
			want: WAFTypeAppGW,
		},
		{
			name: "non-resource-id falls back to FrontDoor",
			id:   "abc123",
			want: WAFTypeFrontDoor,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, WAFTypeFromResourceID(tc.id))
		})
	}
}

func TestParseResourceIDPopulatesResourceType(t *testing.T) {
	rid := config.ParseResourceID("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/p")
	require.Equal(t, ResourceTypeAppGWWAF, rid.ResourceType)

	rid = config.ParseResourceID("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/p")
	require.Equal(t, ResourceTypeFrontDoorWAF, rid.ResourceType)
}

func TestPartitionRIDsByWAFType(t *testing.T) {
	fdID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/fd"
	appgwID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/agw"

	fd, agw := partitionRIDsByWAFType([]string{fdID, appgwID, "abc123"})

	require.Equal(t, []string{fdID, "abc123"}, fd)
	require.Equal(t, []string{appgwID}, agw)
}

func TestLoadAllBackupsFromPathsDispatchesByType(t *testing.T) {
	loaded, err := LoadAllBackupsFromPaths([]string{
		"../testfiles/wrapped-policy-one.json",
		"../testfiles/wrapped-appgw-policy-one.json",
	})
	require.NoError(t, err)

	require.Len(t, loaded.FrontDoor, 1)
	require.Len(t, loaded.AppGW, 1)

	require.Equal(t, "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone", loaded.FrontDoor[0].PolicyID)

	agw := loaded.AppGW[0]
	require.Equal(t, "appgw-policy-one", agw.Name)
	require.Equal(t, WAFTypeAppGW, agw.WAFType)
	require.NotNil(t, agw.Policy.Properties)
	require.NotNil(t, agw.Policy.Properties.ManagedRules)
	require.Len(t, agw.Policy.Properties.ManagedRules.ManagedRuleSets, 1)
}

func TestBuildRestoredAppGWPolicyNewPolicy(t *testing.T) {
	backup := &WrappedAppGWPolicy{
		Name:    "agw1",
		Policy:  newAppGWPolicyForTest(),
		WAFType: WAFTypeAppGW,
	}

	got := BuildRestoredAppGWPolicy(nil, backup, &RestorePoliciesInput{
		ResourceGroup: "rg",
		BaseCLIInput:  BaseCLIInput{SubscriptionID: "00000000-0000-0000-0000-000000000000"},
	})

	require.Equal(t, "rg", got.ResourceGroup)
	require.Equal(t, "agw1", got.Name)
	require.Equal(t, WAFTypeAppGW, got.WAFType)
}

func TestLoadWrappedAppGWPolicyFromFileRejectsInvalid(t *testing.T) {
	_, err := LoadWrappedAppGWPolicyFromFile([]byte(`{"WAFType":"ApplicationGateway"}`))
	require.Error(t, err)
}
