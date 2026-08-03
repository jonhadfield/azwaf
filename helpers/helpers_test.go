package helpers

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetFunctionName(t *testing.T) {
	// GetFunctionName is expected to return the name of itself when called
	require.Equal(t, "helpers.GetFunctionName", GetFunctionName())
}

func callParent() string { return GetParentFunctionName() }

func TestGetParentFunctionName(t *testing.T) {
	// GetParentFunctionName should return the parent caller's name
	require.Equal(t, "helpers.TestGetParentFunctionName", callParent())
}
