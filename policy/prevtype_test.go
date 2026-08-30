package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The review suspected a copy-paste bug: "*prevType = \"ipv4\" inside the ipv6
// branch". It was not one, but the invariant is worth pinning — after a value
// is written inline, prevType must name the family just written; after a line
// break it is reset to "". Drive the handler for both families across every
// incoming prevType state and check it holds.
func TestIPValueHandlersTrackPrevTypeCorrectly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		val      string
		wantType ipFamily
	}{
		{"ipv4", "10.0.0.1/32", ipFamilyV4},
		{"ipv6", "2001:db8::/32", ipFamilyV6},
	} {
		for _, prev := range []ipFamily{ipFamilyNone, ipFamilyV4, ipFamilyV6} {
			t.Run(tc.name+"/after "+prevLabel(prev), func(t *testing.T) {
				var (
					builder     strings.Builder
					prevType    = prev
					valsWritten = 0
				)

				// valsWritten 0 keeps us on the inline path rather than a line break
				handleIPValue(&builder, tc.val, &prevType, &valsWritten, 0, 0, tc.wantType)

				require.Equal(t, tc.val+", ", builder.String())
				require.Equal(t, 1, valsWritten)
				require.Equal(t, tc.wantType, prevType,
					"after writing an %s value prevType must be %q", tc.name, tc.wantType)
			})
		}
	}
}

// On a line break both handlers reset the state, so the next value starts a
// fresh line regardless of which family it belongs to.
func TestIPValueHandlersResetPrevTypeOnLineBreak(t *testing.T) {
	for _, tc := range []struct {
		name    string
		valType ipFamily
		val     string
		prev    ipFamily
	}{
		{"ipv4", ipFamilyV4, "10.0.0.1/32", ipFamilyV4},
		{"ipv4 after ipv6", ipFamilyV4, "10.0.0.1/32", ipFamilyV6},
		{"ipv6", ipFamilyV6, "2001:db8::/32", ipFamilyV6},
		{"ipv6 after ipv4", ipFamilyV6, "2001:db8::/32", ipFamilyV4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				builder     strings.Builder
				prevType    = tc.prev
				valsWritten = 2 // third value on the line forces a break
			)

			handleIPValue(&builder, tc.val, &prevType, &valsWritten, 0, 0, tc.valType)

			require.Equal(t, tc.val+"\n", builder.String())
			require.Zero(t, valsWritten)
			require.Empty(t, prevType, "a line break must reset prevType")
		})
	}
}

func prevLabel(s ipFamily) string {
	if s == ipFamilyNone {
		return "nothing"
	}

	return string(s)
}
