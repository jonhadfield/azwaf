package policy

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/stretchr/testify/require"
)

// marshalPolicy and marshalAppGWOriginal were the same switch over different
// type sets, since merged into marshalOriginal. This pins what it accepts and
// produces; the expectations were written against the two originals.
func TestMarshalOriginalAcceptedTypes(t *testing.T) {
	raw := []byte(`{"already":"bytes"}`)

	fdPolicy := armfrontdoor.WebApplicationFirewallPolicy{Name: toPtr("fd")}
	agwPolicy := armnetwork.WebApplicationFirewallPolicy{Name: toPtr("agw")}

	t.Run("passes byte slices straight through", func(t *testing.T) {
		got, err := marshalOriginal(raw)
		require.NoError(t, err)
		require.Equal(t, raw, got, "no re-encoding, the same slice comes back")
	})

	t.Run("indents a front door policy", func(t *testing.T) {
		got, err := marshalOriginal(fdPolicy)
		require.NoError(t, err)

		want, err := json.MarshalIndent(fdPolicy, "", "    ")
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("unwraps a WrappedPolicy to its inner policy", func(t *testing.T) {
		got, err := marshalOriginal(WrappedPolicy{Name: "outer", Policy: fdPolicy})
		require.NoError(t, err)

		want, err := json.MarshalIndent(fdPolicy, "", "    ")
		require.NoError(t, err)
		require.Equal(t, want, got, "the wrapper metadata is not part of the output")
	})

	t.Run("indents an appgw policy", func(t *testing.T) {
		got, err := marshalOriginal(agwPolicy)
		require.NoError(t, err)

		want, err := json.MarshalIndent(agwPolicy, "", "    ")
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("unwraps a WrappedAppGWPolicy", func(t *testing.T) {
		got, err := marshalOriginal(WrappedAppGWPolicy{Name: "outer", Policy: agwPolicy})
		require.NoError(t, err)

		want, err := json.MarshalIndent(agwPolicy, "", "    ")
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

// Anything else is an error naming the type it got.
func TestMarshalOriginalRejectsOtherTypes(t *testing.T) {
	got, err := marshalOriginal(42)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "int", "the error names the type it was given")
}
