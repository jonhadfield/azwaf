package policy

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadPolicyFromFileMissing(t *testing.T) {
	p, err := LoadPolicyFromFile("missing-file.json")
	require.Error(t, err)
	require.Nil(t, p.ID)
}

func TestCopyPolicyRulesManagedOnly(t *testing.T) {
	one, err := LoadPolicyFromFile("testdata/test-policy-one.json")
	require.NoError(t, err)
	require.NotNil(t, one)
	require.NotNil(t, one.Properties.ManagedRules)

	two, err := LoadPolicyFromFile("testdata/test-policy-two.json")
	require.NoError(t, err)
	require.NotNil(t, two)
	require.NotNil(t, two.Properties.ManagedRules)

	result, err := copyPolicyRules(&one, &two, false, true)
	require.NoError(t, err)
	require.Equal(t, "wafpolicy", *result.Name)

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: one,
		New:      two,
	})
	require.NoError(t, err)
	require.Zero(t, patch.CustomRuleChanges)
	require.Zero(t, patch.ManagedRuleChanges)
	require.NotNil(t, one.Tags)
	require.NotNil(t, two.Tags)
	require.Equal(t, "world", *one.Tags["Hello"])
	require.Equal(t, "mum", *two.Tags["Hello"])
	require.NotNil(t, one.Properties.PolicySettings.RedirectURL)
	require.Equal(t, "https://ischeeseavegetable.com", *one.Properties.PolicySettings.RedirectURL)
	require.NotNil(t, two.Properties.PolicySettings.RedirectURL)
	require.Equal(t, "https://example.com", *two.Properties.PolicySettings.RedirectURL)
	require.Nil(t, DisplayPolicyDiff(one, two))
}

func TestCopyPolicyRulesCustomOnly(t *testing.T) {
	one, err := LoadPolicyFromFile("testdata/test-policy-one.json")
	require.NoError(t, err)
	require.NotNil(t, one)
	require.NotNil(t, one.Properties.ManagedRules)

	two, err := LoadPolicyFromFile("testdata/test-policy-two.json")
	require.NoError(t, err)
	require.NotNil(t, two)
	require.NotNil(t, two.Properties.ManagedRules)

	result, err := copyPolicyRules(&one, &two, true, false)
	require.NoError(t, err)
	require.Equal(t, "wafpolicy", *result.Name)

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: one,
		New:      two,
	})
	require.NoError(t, err)
	require.Zero(t, patch.CustomRuleChanges)
	require.NotZero(t, patch.ManagedRuleChanges)
	require.NotNil(t, one.Tags)
	require.NotNil(t, two.Tags)
	require.Equal(t, "world", *one.Tags["Hello"])
	require.Equal(t, "mum", *two.Tags["Hello"])
	require.NotNil(t, one.Properties.PolicySettings.RedirectURL)
	require.Equal(t, "https://ischeeseavegetable.com", *one.Properties.PolicySettings.RedirectURL)
	require.NotNil(t, two.Properties.PolicySettings.RedirectURL)
	require.Equal(t, "https://example.com", *two.Properties.PolicySettings.RedirectURL)
}

func TestCopyWrappedPolicyRulesManagedOnly(t *testing.T) {
	pOne, _ := LoadPolicyFromFile("testdata/test-policy-one.json")
	pTwo, _ := LoadPolicyFromFile("testdata/test-policy-four.json")

	// without specifying custom or managed, we should get result with empty for both types
	res, _ := copyWrappedPolicyRules(&WrappedPolicy{
		Date:           time.Now(),
		SubscriptionID: "sub-id",
		ResourceGroup:  "resource-group",
		Name:           "name-one",
		Policy:         pOne,
		PolicyID:       "policy-id-one",
		AppVersion:     "app-version",
	}, &WrappedPolicy{
		Date:           time.Now(),
		SubscriptionID: "sub-id",
		ResourceGroup:  "resource-group",
		Name:           "name-two",
		Policy:         pTwo,
		PolicyID:       "policy-id-two",
		AppVersion:     "app-version",
	}, false, true, "Test Version 1.0.0")
	require.Len(t, res.Policy.Properties.ManagedRules.ManagedRuleSets, 2)
	require.Len(t, res.Policy.Properties.CustomRules.Rules, 0)
}

func TestCopyWrappedPolicyRulesCustomOnly(t *testing.T) {
	pOne, _ := LoadPolicyFromFile("testdata/test-policy-one.json")
	pTwo, _ := LoadPolicyFromFile("testdata/test-policy-four.json")

	// without specifying custom or managed, we should get result with empty for both types
	res, _ := copyWrappedPolicyRules(&WrappedPolicy{
		Date:           time.Now(),
		SubscriptionID: "sub-id",
		ResourceGroup:  "resource-group",
		Name:           "name-one",
		Policy:         pOne,
		PolicyID:       "policy-id-one",
		AppVersion:     "app-version",
	}, &WrappedPolicy{
		Date:           time.Now(),
		SubscriptionID: "sub-id",
		ResourceGroup:  "resource-group",
		Name:           "name-two",
		Policy:         pTwo,
		PolicyID:       "policy-id-two",
		AppVersion:     "app-version",
	}, true, false, "Test Version 1.0.0")
	require.Len(t, res.Policy.Properties.ManagedRules.ManagedRuleSets, 1)
	require.Len(t, res.Policy.Properties.CustomRules.Rules, 2)
}

func TestCopyRulesInputChooseOneOnly(t *testing.T) {
	c := &CopyRulesInput{
		Source:           "/subscriptions/291bba3f-e0a5-47bc-a099-3bdcb2a50a05/resourcegroups/waf-resource-group/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafpolicy",
		Target:           "/subscriptions/291bba3f-e0a5-47bc-a099-3bdcb2a50a05/resourcegroups/waf-resource-group/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafpolicy",
		CustomRulesOnly:  true,
		ManagedRulesOnly: true,
		SubscriptionID:   "291bba3f-e0a5-47bc-a099-3bdcb2a50a05",
	}

	err := c.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "choose only one")
}

func TestCopyRulesInputInvalidSourceId(t *testing.T) {
	c := &CopyRulesInput{
		Source:           "invalid",
		Target:           "/subscriptions/291bba3f-e0a5-47bc-a099-3bdcb2a50a05/resourcegroups/waf-resource-group/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafpolicy",
		CustomRulesOnly:  true,
		ManagedRulesOnly: false,
		SubscriptionID:   "291bba3f-e0a5-47bc-a099-3bdcb2a50a05",
	}

	err := c.Validate()
	fmt.Println(err)
	require.Error(t, err)
	require.ErrorContains(t, err, "source")
}

func TestCopyRulesInputInvalidTargetId(t *testing.T) {
	c := &CopyRulesInput{
		Source:           "/subscriptions/291bba3f-e0a5-47bc-a099-3bdcb2a50a05/resourcegroups/waf-resource-group/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafpolicy",
		Target:           "invalid",
		CustomRulesOnly:  true,
		ManagedRulesOnly: false,
		SubscriptionID:   "291bba3f-e0a5-47bc-a099-3bdcb2a50a05",
	}

	err := c.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "target")
}

func TestCopyRulesInputInvalidSubId(t *testing.T) {
	c := &CopyRulesInput{
		Source:           "/subscriptions/291bba3f-e0a5-47bc-a099-3bdcb2a50a05/resourcegroups/waf-resource-group/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafpolicyOne",
		Target:           "/subscriptions/291bba3f-e0a5-47bc-a099-3bdcb2a50a05/resourcegroups/waf-resource-group/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafpolicyTwo",
		CustomRulesOnly:  true,
		ManagedRulesOnly: false,
		SubscriptionID:   "invalid-e0a5-47bc-a099-3bdcb2a50a05",
	}

	err := c.Validate()
	require.Error(t, err)
	fmt.Println(err)
	require.ErrorContains(t, err, "subscription")
}
