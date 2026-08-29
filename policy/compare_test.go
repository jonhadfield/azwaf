package policy

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompareIdentical(t *testing.T) {
	orig := []byte(`{"a":1}`)
	diff, err := compare(orig, orig)
	require.NoError(t, err)
	require.False(t, diff)
}

func TestCompareDifferent(t *testing.T) {
	orig := []byte(`{"a":1}`)
	updated := []byte(`{"a":2}`)
	diff, err := compare(orig, updated)
	require.NoError(t, err)
	require.True(t, diff)
}

func TestCompareInvalidType(t *testing.T) {
	_, err := compare(42, []byte(`{}`))
	require.Error(t, err)
}

// DisplayStringDiffWithDiffTool and compare each had their own copy of "write
// both sides to temp files, run diff -u, treat exit code 2 as failure". This
// pins what each does before they were put on a shared helper.
func TestDisplayStringDiffWithDiffTool(t *testing.T) {
	t.Run("prints a unified diff", func(t *testing.T) {
		out := captureStdout(t, func() {
			require.NoError(t, DisplayStringDiffWithDiffTool("one\ntwo\n", "one\nthree\n"))
		})

		require.Contains(t, out, "-two")
		require.Contains(t, out, "+three")
		require.Contains(t, out, "@@", "unified format, so a hunk header")
	})

	t.Run("identical input produces no diff body", func(t *testing.T) {
		out := captureStdout(t, func() {
			require.NoError(t, DisplayStringDiffWithDiffTool("same\n", "same\n"))
		})

		require.NotContains(t, out, "@@")
	})

	t.Run("leaves no temporary files behind", func(t *testing.T) {
		before, err := os.ReadDir(os.TempDir())
		require.NoError(t, err)

		_ = captureStdout(t, func() {
			require.NoError(t, DisplayStringDiffWithDiffTool("a\n", "b\n"))
		})

		after, err := os.ReadDir(os.TempDir())
		require.NoError(t, err)
		require.LessOrEqual(t, len(after), len(before)+1, "temp files are cleaned up")
	})
}

// compare reports whether the two sides differ, without printing anything.
func TestCompareReportsDifferencesQuietly(t *testing.T) {
	orig := []byte(`{"a":1}`)

	out := captureStdout(t, func() {
		diff, err := compare(orig, []byte(`{"a":2}`))
		require.NoError(t, err)
		require.True(t, diff)
	})
	require.Empty(t, out, "compare detects, it does not display")

	diff, err := compare(orig, orig)
	require.NoError(t, err)
	require.False(t, diff)
}
