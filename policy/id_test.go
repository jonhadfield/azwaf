package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConvertToResourceIDs(t *testing.T) {
	polIdOne := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/apple"
	polIdInvalid := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/apple"
	rids, err := ConvertToResourceIDs([]string{polIdOne}, "test")
	require.NoError(t, err)

	require.Equal(t, "apple", rids[0].Name)
	require.Equal(t, "flying", rids[0].ResourceGroup)
	require.Equal(t, polIdOne, rids[0].Raw)
	require.Equal(t, "0a914e76-4921-4c19-b460-a2d36003525a", rids[0].SubscriptionID)
	require.Equal(t, "Microsoft.Network", rids[0].Provider)

	rids, err = ConvertToResourceIDs([]string{polIdInvalid}, "test")
	require.Error(t, err)
	require.Nil(t, rids)

	rids, err = ConvertToResourceIDs([]string{polIdInvalid, polIdOne}, "test")
	require.Error(t, err)
	require.Nil(t, rids)
}
