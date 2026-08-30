package policy

// These tests exercise azwaf's real Azure call paths against the in-memory
// fake endpoints in internal/azfakes. No network access or credentials are
// required: the Azure SDK's own serialization, paging, and poller code runs
// over the fake transport.

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"
	"github.com/stretchr/testify/require"

	"github.com/jonhadfield/azwaf/internal/azfakes"
)

const azfakesSubID = "10000000-0000-0000-0000-000000000001"

func fdPolicyForFakeTest() armfrontdoor.WebApplicationFirewallPolicy {
	enabled := armfrontdoor.PolicyEnabledStateEnabled
	mode := armfrontdoor.PolicyModePrevention

	return armfrontdoor.WebApplicationFirewallPolicy{
		Location: toPtr("Global"),
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			PolicySettings: &armfrontdoor.PolicySettings{
				EnabledState: &enabled,
				Mode:         &mode,
			},
		},
	}
}

func TestFakeSessionListsAndFiltersFrontDoorPolicies(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())
	idTwo := st.AddFrontDoorPolicy("rg-two", "fd-two", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// no filter: both policies in the subscription are returned
	o, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{SubscriptionID: azfakesSubID})
	require.NoError(t, err)
	require.Len(t, o.Policies, 2)

	// filtered by resource id: only the matching policy is returned, wrapped
	// with the identity parsed from its id
	o, err = GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    azfakesSubID,
		FilterResourceIDs: []string{idTwo},
	})
	require.NoError(t, err)
	require.Len(t, o.Policies, 1)
	require.Equal(t, "fd-two", o.Policies[0].Name)
	require.Equal(t, "rg-two", o.Policies[0].ResourceGroup)
	require.Equal(t, idTwo, o.Policies[0].PolicyID)
}

func TestFakeSessionListsAndFiltersAppGWPolicies(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())
	idTwo := st.AddAppGWPolicy("rg-two", "agw-two", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	all, err := GetWrappedAppGWPoliciesFromRawIDs(s, GetWrappedPoliciesInput{SubscriptionID: azfakesSubID})
	require.NoError(t, err)
	require.Len(t, all, 2)

	for _, wp := range all {
		require.Equal(t, WAFTypeAppGW, wp.WAFType)
	}

	filtered, err := GetWrappedAppGWPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    azfakesSubID,
		FilterResourceIDs: []string{idTwo},
	})
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	require.Equal(t, "agw-two", filtered[0].Name)
	require.Equal(t, idTwo, filtered[0].PolicyID)
}

func TestProcessAppGWPolicyChangesPushesToFakeAzure(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	updated := newAppGWPolicyForTest()
	v31 := "3.1"
	updated.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion = &v31

	require.NoError(t, ProcessAppGWPolicyChanges(&ProcessAppGWPolicyChangesInput{
		Session:          s,
		PolicyName:       "agw-one",
		SubscriptionID:   azfakesSubID,
		ResourceGroup:    "rg-one",
		PolicyPostChange: updated,
	}))

	pushed := st.PushedAppGW()
	require.Len(t, pushed, 1)
	require.Equal(t, "agw-one", pushed[0].Name)
	require.Equal(t, "rg-one", pushed[0].ResourceGroup)
	require.Equal(t, "3.1", *pushed[0].Policy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)

	// the store reflects the update, as a follow-up Get would see it
	got, ok := st.AppGWPolicy("rg-one", "agw-one")
	require.True(t, ok)
	require.Equal(t, "3.1", *got.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
}

func TestProcessAppGWPolicyChangesDryRunDoesNotPush(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	updated := newAppGWPolicyForTest()
	v31 := "3.1"
	updated.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion = &v31

	require.NoError(t, ProcessAppGWPolicyChanges(&ProcessAppGWPolicyChangesInput{
		Session:          s,
		PolicyName:       "agw-one",
		SubscriptionID:   azfakesSubID,
		ResourceGroup:    "rg-one",
		PolicyPostChange: updated,
		DryRun:           true,
	}))

	require.Empty(t, st.PushedAppGW())

	// the stored policy is untouched
	got, ok := st.AppGWPolicy("rg-one", "agw-one")
	require.True(t, ok)
	require.Equal(t, "3.2", *got.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
}

func TestProcessPolicyChangesFrontDoorPushesToFakeAzure(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// fetch through the fake, modify, and push — the same shape restore uses
	existing, err := GetRawPolicy(s, azfakesSubID, "rg-one", "fd-one")
	require.NoError(t, err)

	detection := armfrontdoor.PolicyModeDetection
	existing.Properties.PolicySettings.Mode = &detection

	require.NoError(t, ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       "fd-one",
		SubscriptionID:   azfakesSubID,
		ResourceGroup:    "rg-one",
		PolicyPostChange: *existing,
	}))

	pushed := st.PushedFrontDoor()
	require.Len(t, pushed, 1)
	require.Equal(t, "fd-one", pushed[0].Name)
	require.Equal(t, armfrontdoor.PolicyModeDetection, *pushed[0].Policy.Properties.PolicySettings.Mode)
}

func TestAppGWRestoreRoundTripAgainstFakeAzure(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	policyID := st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// write a backup carrying an older ruleset version than the live policy
	backupPolicy := newAppGWPolicyForTest()
	v31 := "3.1"
	backupPolicy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion = &v31

	backup := WrappedAppGWPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-one",
		Name:           "agw-one",
		Policy:         backupPolicy,
		PolicyID:       policyID,
		WAFType:        WAFTypeAppGW,
	}

	backupsDir := t.TempDir()
	require.NoError(t, BackupAppGWPolicy(&backup, BackupDestination{Path: backupsDir, FailFast: true, Quiet: true}))

	loaded, err := LoadAllBackupsFromPaths([]string{backupsDir})
	require.NoError(t, err)
	require.Empty(t, loaded.FrontDoor)
	require.Len(t, loaded.AppGW, 1)

	// restore it: Force skips the interactive confirmation
	require.NoError(t, restoreAppGWBackups(s, &RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Force:        true,
	}, loaded.AppGW))

	pushed := st.PushedAppGW()
	require.Len(t, pushed, 1)
	require.Equal(t, "agw-one", pushed[0].Name)

	got, ok := st.AppGWPolicy("rg-one", "agw-one")
	require.True(t, ok)
	require.Equal(t, "3.1", *got.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
}

func TestGetRawAppGWPolicyNotFoundViaFake(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// the fake returns a typed *azcore.ResponseError with status 404, which
	// must flow through GetRawAppGWPolicy's %w wrapping into the typed check
	_, err = GetRawAppGWPolicy(s, azfakesSubID, "rg-none", "missing")
	require.Error(t, err)
	require.True(t, isAppGWNotFound(err))
}
