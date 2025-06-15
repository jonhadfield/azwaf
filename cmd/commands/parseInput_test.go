package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNetsFromString(t *testing.T) {
	validOne := "8.8.8.8, 4.4.4.4" + defaultIPv4Prefix + ",10.10.10.0/24 "
	nets, err := addrsFromString(validOne)
	require.NoError(t, err)
	require.Len(t, nets, 3)

	invalidOne := "8.8.8.8, 4.4.4.4/33,10.10.10.0/24 "
	_, err = addrsFromString(invalidOne)
	require.Error(t, err)

	invalidTwo := "8.8.256.8, 4.4.4.4" + defaultIPv4Prefix + ",10.10.10.0/24 "
	_, err = addrsFromString(invalidTwo)
	require.Error(t, err)
}
