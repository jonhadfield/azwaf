package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToJSONBasic(t *testing.T) {
	s, err := toJSON(`{"a":1}`)
	require.NoError(t, err)
	require.Equal(t, `{"a":1}`, s)

	b, _ := json.Marshal(`hello`)
	s, err = toJSON(b)
	require.NoError(t, err)
	require.Equal(t, `"hello"`, s)

	_, err = toJSON(123)
	require.Error(t, err)
}
