package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetFunctionName(t *testing.T) {
	// GetFunctionName returns the name of the function that calls it
	require.Equal(t, "helpers.TestGetFunctionName", GetFunctionName())
}

func callParent() string { return GetParentFunctionName() }

func TestGetParentFunctionName(t *testing.T) {
	// GetParentFunctionName should return the parent caller's name
	require.Equal(t, "helpers.TestGetParentFunctionName", callParent())
}
