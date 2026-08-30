package policy

// Regression tests for whole-section patch counting: a policy gaining a
// customRules section where none existed produces a single jsondiff op at
// exactly /properties/customRules (no trailing slash), which previously
// counted as zero rule changes and caused restores to be skipped as
// "identical".

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/stretchr/testify/require"
)

func TestGenerateAppGWPolicyPatchCountsWholeSectionAdd(t *testing.T) {
	original := newAppGWPolicyForTest() // no custom rules section

	updated := newAppGWPolicyForTest()
	updated.Properties.CustomRules = []*armnetwork.WebApplicationFirewallCustomRule{
		{Name: toPtr("cr-one")},
	}

	out, err := GenerateAppGWPolicyPatch(original, updated)
	require.NoError(t, err)

	require.GreaterOrEqual(t, out.CustomRuleAdditions, 1)
	require.GreaterOrEqual(t, out.CustomRuleChanges, 1)
	require.Zero(t, out.ManagedRuleChanges)
	require.GreaterOrEqual(t, out.TotalRuleDifferences, 1)
}

func TestGeneratePolicyPatchCountsWholeSectionAddFrontDoor(t *testing.T) {
	original := fdPolicyForFakeTest() // no custom rules section

	updated := fdPolicyForFakeTest()
	updated.Properties.CustomRules = &armfrontdoor.CustomRuleList{
		Rules: []*armfrontdoor.CustomRule{{Name: toPtr("cr-one")}},
	}

	out, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: original, New: updated})
	require.NoError(t, err)

	require.GreaterOrEqual(t, out.CustomRuleAdditions, 1)
	require.GreaterOrEqual(t, out.CustomRuleChanges, 1)
	require.Zero(t, out.ManagedRuleChanges)
	require.GreaterOrEqual(t, out.TotalRuleDifferences, 1)
}
