package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetWAFPolicyResourceID(t *testing.T) {
	raw := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone"

	rid, err := GetWAFPolicyResourceID(nil, GetWAFPolicyResourceIDInput{RawPolicyID: raw})
	require.NoError(t, err)
	require.Equal(t, "mypolicyone", rid.Name)

	cfg := []byte("policy_aliases:\n  p1: " + raw + "\n")
	path := filepath.Join(t.TempDir(), "c.yaml")
	require.NoError(t, os.WriteFile(path, cfg, 0o600))

	rid, err = GetWAFPolicyResourceID(nil, GetWAFPolicyResourceIDInput{RawPolicyID: "p1", ConfigPath: path})
	require.NoError(t, err)
	require.Equal(t, "mypolicyone", rid.Name)

	_, err = GetWAFPolicyResourceID(nil, GetWAFPolicyResourceIDInput{RawPolicyID: "missing"})
	require.Error(t, err)
}
