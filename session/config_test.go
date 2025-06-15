package session

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/require"
)

func TestReadFileBytes(t *testing.T) {
    base := t.TempDir()
    path := filepath.Join(base, "f.txt")
    data := []byte("hello")
    require.NoError(t, os.WriteFile(path, data, 0o600))

    b, err := ReadFileBytes(path)
    require.NoError(t, err)
    require.Equal(t, data, b)
}

func TestReadFileBytesError(t *testing.T) {
    _, err := ReadFileBytes("/no/such/file")
    require.Error(t, err)
    require.Contains(t, err.Error(), "helpers.GetFunctionName")
}

func TestLoadFileConfig(t *testing.T) {
    data := []byte("policy_aliases:\n  foo: bar\n")
    tmp := filepath.Join(t.TempDir(), "c.yaml")
    require.NoError(t, os.WriteFile(tmp, data, 0o600))

    cfg, err := LoadFileConfig(tmp)
    require.NoError(t, err)
    require.Equal(t, "bar", cfg.PolicyAliases["foo"])

    cfg, err = LoadFileConfig("")
    require.NoError(t, err)
    require.Nil(t, cfg.PolicyAliases)
}
