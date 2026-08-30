package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetFunctionName(t *testing.T) {
	// GetFunctionName returns the name of the function that calls it
	require.Equal(t, "helpers.TestGetFunctionName", GetFunctionName())
}

// Callers in policy/ used to reach this through a two-hop wrapper that counted
// stack frames. They now call it directly, so pin that it names the immediate
// caller wherever it is invoked from, including inside a method.
type namer struct{}

func (namer) name() string { return GetFunctionName() }

func TestGetFunctionNameNamesTheImmediateCaller(t *testing.T) {
	require.Equal(t, "helpers.namer.name", namer{}.name())
}
