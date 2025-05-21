package config

import (
	"os"
	"path/filepath"
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

func TestParseResourceIDInvalid(t *testing.T) {
	rid := ParseResourceID("/subscriptions/123/resourceGroups/one")
	require.Empty(t, rid.SubscriptionID)
	require.Empty(t, rid.ResourceGroup)
	require.Empty(t, rid.Provider)
	require.Empty(t, rid.Name)
}

func TestNewResourceID(t *testing.T) {
	rid := NewResourceID("sub", "rg", "provider", "name")
	require.Equal(t, "sub", rid.SubscriptionID)
	require.Equal(t, "rg", rid.ResourceGroup)
	require.Equal(t, "provider", rid.Provider)
	require.Equal(t, "name", rid.Name)
	require.Equal(t,
		"/subscriptions/sub/resourceGroups/rg/providers/provider/name",
		rid.Raw,
	)
}

func TestLoadFileConfig(t *testing.T) {
	data := []byte("policy_aliases:\n  foo: bar\n")
	tmp := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(tmp, data, 0o600))

	cfg, err := LoadFileConfig(tmp)
	require.NoError(t, err)
	require.Equal(t, "bar", cfg.PolicyAliases["foo"])

	// empty path returns empty config
	cfg, err = LoadFileConfig("")
	require.NoError(t, err)
	require.Nil(t, cfg.PolicyAliases)
}
