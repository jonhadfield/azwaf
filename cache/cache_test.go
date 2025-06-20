package cache

import (
	"path/filepath"
	"testing"

	"github.com/jonhadfield/azwaf/session"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/buntdb"
)

func newTestSession(t *testing.T) *session.Session {
	t.Helper()
	s := &session.Session{}
	s.CachePath = filepath.Join(t.TempDir(), "cache.db")
	db, err := buntdb.Open(s.CachePath)
	require.NoError(t, err)
	s.Cache = db
	return s
}

func TestWriteRead(t *testing.T) {
	s := newTestSession(t)
	defer func() { require.NoError(t, s.Cache.Close()) }()

	require.NoError(t, Write(s, "k", "v"))

	v, err := Read(s, "k")
	require.NoError(t, err)
	require.Equal(t, "v", v)
}

func TestReadMissing(t *testing.T) {
	s := newTestSession(t)
	defer func() { require.NoError(t, s.Cache.Close()) }()

	v, err := Read(s, "missing")
	require.NoError(t, err)
	require.Empty(t, v)
}
