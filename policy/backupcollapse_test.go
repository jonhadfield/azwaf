package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/stretchr/testify/require"
)

// Characterisation test for the two backup functions before they were collapsed
// onto a shared implementation. They differ only in the WAF type they stamp and
// the wording they log, so those are what this pins, along with the file name
// format both produce.
func TestBackupPolicyFileNameAndWAFType(t *testing.T) {
	nameRe := regexp.MustCompile(`^sub\+rg\+pol\+\d{14}\.json$`)

	t.Run("front door", func(t *testing.T) {
		dir := t.TempDir()
		p := WrappedPolicy{
			SubscriptionID: "sub", ResourceGroup: "rg", Name: "pol",
			Policy: armfrontdoor.WebApplicationFirewallPolicy{Name: toPtr("pol")},
		}

		require.NoError(t, BackupPolicy(&p, nil, "", true, true, dir))

		files, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, files, 1)
		require.Regexp(t, nameRe, files[0].Name())

		data, rerr := os.ReadFile(filepath.Join(dir, files[0].Name()))
		require.NoError(t, rerr)

		var peek struct {
			WAFType string
			Name    string
			Date    string
		}
		require.NoError(t, json.Unmarshal(data, &peek))
		require.Equal(t, WAFTypeFrontDoor, peek.WAFType, "front door backups are stamped FrontDoor")
		require.Equal(t, "pol", peek.Name)
		require.NotEmpty(t, peek.Date, "the date is stamped at backup time")

		// the in-memory value is stamped too, not just the file
		require.Equal(t, WAFTypeFrontDoor, p.WAFType)
		require.False(t, p.Date.IsZero())
	})

	t.Run("app gateway", func(t *testing.T) {
		dir := t.TempDir()
		p := WrappedAppGWPolicy{
			SubscriptionID: "sub", ResourceGroup: "rg", Name: "pol",
			Policy: armnetwork.WebApplicationFirewallPolicy{Name: toPtr("pol")},
		}

		require.NoError(t, BackupAppGWPolicy(&p, nil, "", true, true, dir))

		files, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, files, 1)
		require.Regexp(t, nameRe, files[0].Name())

		data, rerr := os.ReadFile(filepath.Join(dir, files[0].Name()))
		require.NoError(t, rerr)

		var peek struct{ WAFType string }
		require.NoError(t, json.Unmarshal(data, &peek))
		require.Equal(t, WAFTypeAppGW, peek.WAFType, "appgw backups are stamped ApplicationGateway")

		require.Equal(t, WAFTypeAppGW, p.WAFType)
		require.False(t, p.Date.IsZero())
	})
}

// An existing WAFType is not overwritten by either function.
func TestBackupPolicyKeepsExistingWAFType(t *testing.T) {
	dir := t.TempDir()
	p := WrappedPolicy{SubscriptionID: "s", ResourceGroup: "r", Name: "n", WAFType: WAFTypeAppGW}

	require.NoError(t, BackupPolicy(&p, nil, "", true, true, dir))
	require.Equal(t, WAFTypeAppGW, p.WAFType, "an already-set type is left alone")
}

// With no path and no blob client there is nothing to write, and that is not an
// error — backupPolicies relies on it when only uploading.
func TestBackupPolicyWithNoDestination(t *testing.T) {
	p := WrappedPolicy{SubscriptionID: "s", ResourceGroup: "r", Name: "n"}
	require.NoError(t, BackupPolicy(&p, nil, "", true, true, ""))

	a := WrappedAppGWPolicy{SubscriptionID: "s", ResourceGroup: "r", Name: "n"}
	require.NoError(t, BackupAppGWPolicy(&a, nil, "", true, true, ""))
}

// The status line is printed unless quiet, and names the policy type.
func TestBackupPolicyStatusLine(t *testing.T) {
	dir := t.TempDir()
	p := WrappedPolicy{SubscriptionID: "s", ResourceGroup: "r", Name: "fd-one"}
	out := captureStdout(t, func() {
		require.NoError(t, BackupPolicy(&p, nil, "", true, false, dir))
	})
	require.Contains(t, out, "backing up Policy: fd-one")

	a := WrappedAppGWPolicy{SubscriptionID: "s", ResourceGroup: "r", Name: "agw-one"}
	out = captureStdout(t, func() {
		require.NoError(t, BackupAppGWPolicy(&a, nil, "", true, false, t.TempDir()))
	})
	require.Contains(t, out, "backing up AppGW Policy: agw-one")
	require.True(t, strings.Contains(out, "agw-one"))
}
