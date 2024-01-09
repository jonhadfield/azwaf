package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// write tests for ParseResourceID
func TestParseResourceID(t *testing.T) {
	// valid resource id
	rawResourceId := "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myrg/providers/Microsoft.Network/frontDoorWebApps/myfdwa"
	rid := ParseResourceID(rawResourceId)
	require.Equal(t, "12345678-1234-1234-1234-123456789012", rid.SubscriptionID)
	require.Equal(t, "myrg", rid.ResourceGroup)
	require.Equal(t, "Microsoft.Network", rid.Provider)
	require.Equal(t, "myfdwa", rid.Name)
	require.Equal(t, rawResourceId, rid.Raw)
}
