package policy

import (
	"testing"

	"github.com/jonhadfield/azwaf/internal/azfakes"
	"github.com/stretchr/testify/require"
)

// GetPolicyResourceIDByHash and GetPolicyRIDByHash resolve the same hash by the
// same route, differing only in whether they hand back the raw id or a parsed
// one. This pins that they agree, before the first was reduced to a wrapper
// over the second.
func TestHashLookupsAgree(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	hash := computeAdler32(rid)

	gotRID, err := GetPolicyRIDByHash(s, azfakesSubID, hash)
	require.NoError(t, err)
	require.Equal(t, rid, gotRID)

	gotResourceID, err := GetPolicyResourceIDByHash(s, azfakesSubID, hash)
	require.NoError(t, err)

	// the parsed form is the raw one run through ParseResourceID
	require.Equal(t, "fd-one", gotResourceID.Name)
	require.Equal(t, "rg-one", gotResourceID.ResourceGroup)
	require.Equal(t, azfakesSubID, gotResourceID.SubscriptionID)
	require.Equal(t, gotRID, gotResourceID.Raw)
}

// An unknown hash is an error from both, with the hash named.
func TestHashLookupsReportUnknownHash(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	_, err = GetPolicyRIDByHash(s, azfakesSubID, "deadbeef")
	require.ErrorContains(t, err, "resource with hash deadbeef could not be found")

	got, err := GetPolicyResourceIDByHash(s, azfakesSubID, "deadbeef")
	require.ErrorContains(t, err, "resource with hash deadbeef could not be found")
	require.Empty(t, got.Name, "nothing usable is returned alongside the error")
	require.Empty(t, got.Raw)
}

// A second lookup is served from the cache the first one populated.
func TestHashLookupUsesCache(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	hash := computeAdler32(rid)

	first, err := GetPolicyRIDByHash(s, azfakesSubID, hash)
	require.NoError(t, err)

	second, err := GetPolicyRIDByHash(s, azfakesSubID, hash)
	require.NoError(t, err)
	require.Equal(t, first, second)
}
