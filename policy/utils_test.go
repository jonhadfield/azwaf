package policy

import (
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/stretchr/testify/require"
)

func TestDereferenceStrings(t *testing.T) {
	strs := dereferenceStrings([]*string{toPtr("hello"), toPtr("world")})
	require.Equal(t, []string{"hello", "world"}, strs)
}

func TestInt32Ptr(t *testing.T) {
	i := int32Ptr(1)
	require.Equal(t, int32(1), *i)
}

func TestParseRuleSetName(t *testing.T) {
	key, val, err := parseRuleSetName("hello_world")
	require.NoError(t, err)
	require.Equal(t, "hello", key)
	require.Equal(t, "world", val)
	require.NotEmpty(t, key)

	_, _, err = parseRuleSetName("helloworld")
	require.Error(t, err)
	require.Contains(t, err.Error(), "underscore")

	_, _, err = parseRuleSetName("")
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

func TestLoadIPsFromPathMissingPath(t *testing.T) {
	t.Parallel()

	ips, err := loadIPsFromPath("missing-path")
	require.Error(t, err)
	require.Nil(t, ips)
}

func TestLoadIPsFromPathSingleFile(t *testing.T) {
	t.Parallel()

	ips, err := loadIPsFromPath(filepath.Join("testdata", "nets.txt"))
	require.NoError(t, err)
	require.Len(t, ips, 2)
}

func TestLoadIPsFromPathSingleFileWithInvalid(t *testing.T) {
	t.Parallel()

	ips, err := loadIPsFromPath(filepath.Join("testdata", "nets4.txt"))
	require.Error(t, err)
	require.Empty(t, ips)
}

func TestLoadIPsFromEmptyDir(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	ips, err := loadIPsFromPath(tempDir)
	require.Error(t, err)
	require.Nil(t, ips)
}

func TestLoadIPsFromDirWithMultiple(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	require.NoError(t, copyFile(filepath.Join("testdata", "nets.txt"), filepath.Join(tempDir, "nets.txt")))
	require.NoError(t, copyFile(filepath.Join("testdata", "nets2.txt"), filepath.Join(tempDir, "nets2.txt")))
	require.NoError(t, copyFile(filepath.Join("testdata", "nets3.txt"), filepath.Join(tempDir, "nets3.txt")))

	ips, err := loadIPsFromPath(tempDir)
	require.NoError(t, err)
	require.Len(t, ips, 7)
	// 155.0.0.0/8 is contained in two files, hence only testing for six
	require.Contains(t, ips, netip.MustParsePrefix("155.0.0.0/8"))
	require.Contains(t, ips, netip.MustParsePrefix("155.1.0.0/24"))
	require.Contains(t, ips, netip.MustParsePrefix("201.0.0.0/8"))
	require.Contains(t, ips, netip.MustParsePrefix("201.1.0.0/24"))
	require.Contains(t, ips, netip.MustParsePrefix("200.0.0.0/8"))
	require.Contains(t, ips, netip.MustParsePrefix("201.1.0.0/24"))
}

func TestIsIPv4IPv6(t *testing.T) {
	require.True(t, IsIPv4("192.168.1.1"))
	require.False(t, IsIPv4("2001:db8::1"))
	require.True(t, IsIPv6("2001:db8::1"))
	require.False(t, IsIPv6("10.0.0.1"))
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}

	defer func() { _ = srcFile.Close() }()

	destFile, err := os.Create(dst) // creates if file doesn't exist
	if err != nil {
		return err
	}

	defer func() { _ = destFile.Close() }()

	_, err = io.Copy(destFile, srcFile) // check first var for number of bytes copied
	if err != nil {
		return err
	}

	return destFile.Sync()
}
