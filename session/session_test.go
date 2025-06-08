package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "a", "b")

	require.NoError(t, createDirectory(target))

	info, err := os.Stat(target)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	// should not error if directory already exists
	require.NoError(t, createDirectory(target))
}
