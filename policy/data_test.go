package policy

import (
	"fmt"
	"testing"

	"github.com/jonhadfield/azwaf/config"

	"github.com/stretchr/testify/require"
)

func TestParseResourceID(t *testing.T) {
	rawID := "/subscriptions/46a10210-e50b-4a74-aefd-059cc0ec8b5e/resourceGroups/example-group/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/example-policy-one"
	resourceID := config.ParseResourceID(rawID)
	require.Equal(t, "46a10210-e50b-4a74-aefd-059cc0ec8b5e", resourceID.SubscriptionID)
	require.Equal(t, "example-group", resourceID.ResourceGroup)
	require.Equal(t, "example-policy-one", resourceID.Name)
	require.Equal(t, rawID, resourceID.Raw)
	require.Equal(t, "Microsoft.Network", resourceID.Provider)

	missingSubIDRawID := "/subscriptions/resourceGroups/example-group/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/example-policy-one"
	resourceID = config.ParseResourceID(missingSubIDRawID)
	require.Empty(t, resourceID.Name)
}

func TestLoadWrappedPolicyFromFile(t *testing.T) {
	wp, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	require.Equal(t, "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone", wp.PolicyID)

	_, err = LoadWrappedPolicyFromFile("testfiles/non-existant-wrapped-policy-one.json")
	require.Error(t, err)
}

// TestLoadBackupsFromPathsEmpty tests that an empty slice of paths returns an error
func TestLoadBackupsFromPathsEmpty(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{})
	require.Error(t, err)
	require.Nil(t, wp)
}

// TestLoadBackupsFromPathsMissingPath tests that a missing path returns an error
func TestLoadBackupsFromPathsMissingPath(t *testing.T) {
	wp, err := LoadBackupsFromPaths([]string{""})
	fmt.Println(err)
	require.Error(t, err)
	require.Nil(t, wp)
}
