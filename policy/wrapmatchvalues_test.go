package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Characterisation test pinning wrapMatchValues' exact output. Originally
// written before
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
			// two long values used to share a line, making it 88 characters and
			// widening the column to match. They now get a line each.
			"long v6 wraps on length",
			[]string{
				"2001:0db8:aaaa:bbbb:cccc:dddd:eeee:ffff/128",
				"2001:0db8:aaaa:bbbb:cccc:dddd:eeee:0001/128",
				"2001:db8::9/128",
			},
			"2001:0db8:aaaa:bbbb:cccc:dddd:eeee:ffff/128,\n2001:0db8:aaaa:bbbb:cccc:dddd:eeee:0001/128\n2001:db8::9/128",
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

// Long match values used to set the width of the column they sit in, and
// through it the whole custom-rules table: a single 300-character value made
// the table 400 characters wide. No line may now exceed lineLengthLimit.
func TestWrapMatchValuesBoundsLineLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		vals []string
	}{
		{"one value far over the limit", []string{strings.Repeat("a", 300)}},
		{"one value just over", []string{strings.Repeat("b", lineLengthLimit+1)}},
		{"several long values", []string{
			strings.Repeat("c", 80), strings.Repeat("d", 80), strings.Repeat("e", 80),
		}},
		{"long and short mixed", []string{
			"10.0.0.1/32", strings.Repeat("f", 200), "10.0.0.2/32",
		}},
		{"many short values", []string{
			"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.4/32", "10.0.0.5/32",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vals := tc.vals

			ptrs := make([]*string, 0, len(vals))
			for i := range vals {
				ptrs = append(ptrs, &vals[i])
			}

			for _, line := range strings.Split(wrapMatchValues(ptrs, true), "\n") {
				require.LessOrEqual(t, len([]rune(line)), lineLengthLimit,
					"line exceeds the limit and would widen the column: %q", line)
			}
		})
	}
}

// Wrapping must not lose or reorder any part of a value.
func TestWrapMatchValuesPreservesContent(t *testing.T) {
	vals := []string{strings.Repeat("a", 150), "10.0.0.1/32", strings.Repeat("b", 70)}

	ptrs := make([]*string, 0, len(vals))
	for i := range vals {
		ptrs = append(ptrs, &vals[i])
	}

	got := wrapMatchValues(ptrs, true)

	// strip the wrapping and separators, leaving just the values back to back
	flat := strings.NewReplacer("\n", "", ", ", "", ",", "").Replace(got)
	require.Equal(t, strings.Join(vals, ""), flat)
}

// wrapLine splits at commas where it can, and only mid-value when a single
// value cannot fit on a line of its own.
func TestWrapLineSplitsAtCommasWherePossible(t *testing.T) {
	line := "aaaa, bbbb, cccc, dddd"
	require.Equal(t, []string{"aaaa, bbbb,", "cccc, dddd"}, wrapLine(line, 12))

	// a value longer than the limit is split mid-value
	require.Equal(t, []string{"aaaaaa", "aaaa"}, wrapLine(strings.Repeat("a", 10), 6))

	// a line already within the limit is untouched
	require.Equal(t, []string{"short"}, wrapLine("short", 60))
}
