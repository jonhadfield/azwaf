package policy

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/stretchr/testify/require"
)

func TestDeRefStrs(t *testing.T) {
	strs := deRefStrs([]*string{toPtr("hello"), toPtr("world")})
	require.Equal(t, []string{"hello", "world"}, strs)
}

func TestInt32ToPointer(t *testing.T) {
	i := Int32ToPointer(1)
	require.Equal(t, int32(1), *i)
}

func TestSplitRuleSetName(t *testing.T) {
	key, val, err := splitRuleSetName("hello_world")
	require.NoError(t, err)
	require.Equal(t, "hello", key)
	require.Equal(t, "world", val)
	require.NotEmpty(t, key)

	_, _, err = splitRuleSetName("helloworld")
	require.Error(t, err)
	require.Contains(t, err.Error(), "underscore")

	_, _, err = splitRuleSetName("")
	require.Error(t, err)
}

func TestActionStringToActionType(t *testing.T) {
	at, err := actionStringToActionType("block")
	require.NoError(t, err)
	require.Equal(t, armfrontdoor.ActionTypeBlock, at)

	at, err = actionStringToActionType("Block")
	require.NoError(t, err)
	require.Equal(t, armfrontdoor.ActionTypeBlock, at)

	at, err = actionStringToActionType("LOG")
	require.NoError(t, err)
	require.Equal(t, armfrontdoor.ActionTypeLog, at)

	at, err = actionStringToActionType("Allow")
	require.NoError(t, err)
	require.Equal(t, armfrontdoor.ActionTypeAllow, at)

	_, err = actionStringToActionType("wibble")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected action")
}
