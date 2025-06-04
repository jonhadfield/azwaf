package policy

import (
	"github.com/stretchr/testify/require"
	"testing"
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
