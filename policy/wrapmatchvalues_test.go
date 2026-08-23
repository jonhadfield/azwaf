package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Characterisation test pinning wrapMatchValues' exact output before
// handleIPv4Value and handleIPv6Value were collapsed into one handler. The
// expectations were captured from the two-function version, so any difference
// after the refactor is a behaviour change rather than a tidy-up.
//
// "v4 url v4" is the case that constrains the design: handleURLValue clears
// prevType without resetting valsWritten, so a value can arrive with prevType
// "" while a line is already part-written. That path skips the line-break
// checks, which is why the "" case cannot simply be folded in with the others.
func TestWrapMatchValuesFormatting(t *testing.T) {
	for _, tc := range []struct {
		name string
		vals []string
		want string
	}{
		{
			"v4 only",
			[]string{"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.4/32"},
			"10.0.0.1/32, 10.0.0.2/32, 10.0.0.3/32\n10.0.0.4/32",
		},
		{
			"v6 only",
			[]string{"2001:db8::1/128", "2001:db8::2/128", "2001:db8::3/128"},
			"2001:db8::1/128, 2001:db8::2/128, 2001:db8::3/128\n",
		},
		{
			"mixed families",
			[]string{"10.0.0.1/32", "2001:db8::1/128", "10.0.0.2/32", "2001:db8::2/128"},
			"10.0.0.1/32, 2001:db8::1/128, 10.0.0.2/32\n2001:db8::2/128",
		},
		{
			"url then v4",
			[]string{"https://example.com/a", "10.0.0.1/32", "10.0.0.2/32"},
			"https://example.com/a\n10.0.0.1/32, 10.0.0.2/32",
		},
		{
			"v4 url v4 — prevType cleared mid-line",
			[]string{"10.0.0.1/32", "https://example.com/a", "10.0.0.2/32", "10.0.0.3/32"},
			"10.0.0.1/32, https://example.com/a\n10.0.0.2/32, 10.0.0.3/32\n",
		},
		{
			"long v6 wraps on length",
			[]string{
				"2001:0db8:aaaa:bbbb:cccc:dddd:eeee:ffff/128",
				"2001:0db8:aaaa:bbbb:cccc:dddd:eeee:0001/128",
				"2001:db8::9/128",
			},
			"2001:0db8:aaaa:bbbb:cccc:dddd:eeee:ffff/128, 2001:0db8:aaaa:bbbb:cccc:dddd:eeee:0001/128\n2001:db8::9/128",
		},
		{
			"geo mixed",
			[]string{"GB", "US", "10.0.0.1/32", "FR", "2001:db8::1/128"},
			"GB, US, 10.0.0.1/32, FR, 2001:db8::1/128",
		},
		{
			"single value",
			[]string{"10.0.0.1/32"},
			"10.0.0.1/32",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vals := tc.vals

			ptrs := make([]*string, 0, len(vals))
			for i := range vals {
				ptrs = append(ptrs, &vals[i])
			}

			require.Equal(t, tc.want, wrapMatchValues(ptrs, true))
		})
	}
}
