package policy

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratePolicyToRestoreBackupOnly(t *testing.T) {
	policyTwo, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyTwoStatic, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that if only backup provided, that backup is returned
	generatedPolicyOne := GeneratePolicyToRestore(&WrappedPolicy{}, &policyTwo, &RestorePoliciesInput{})
	require.NotNil(t, generatedPolicyOne)
	require.True(t, reflect.DeepEqual(generatedPolicyOne.Policy, policyTwoStatic.Policy))
}

func TestGeneratePolicyToRestoreBackupWithoutOptions(t *testing.T) {
	policyOne, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwo, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyTwoStatic, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that providing two Policies without options returns Original with backup rules replacing Original's
	generatedPolicyTwo := GeneratePolicyToRestore(&policyOne, &policyTwo, &RestorePoliciesInput{})
	require.NotNil(t, generatedPolicyTwo)
	require.True(t, reflect.DeepEqual(generatedPolicyTwo.Policy, policyTwoStatic.Policy))
}

func TestGeneratePolicyToRestoreBackupCustomOnly(t *testing.T) {
	policyOne, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwo, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyOneStatic, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwoStatic, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that providing two Policies (with both different Custom rules and Managed rules) with option to only replace
	// Custom rules with backup's Custom rules
	generatedPolicyThree := GeneratePolicyToRestore(&policyOne, &policyTwo, &RestorePoliciesInput{
		CustomRulesOnly: true,
	})

	require.NotNil(t, generatedPolicyThree)
	// generated Policy's Custom rules should be identical to Policy two's
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.CustomRules, policyTwoStatic.Policy.Properties.CustomRules))
	// generated Policy's Custom rules should be different from Policy one's Custom rules
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.CustomRules, policyOneStatic.Policy.Properties.CustomRules))
	// generated Policy's Managed rules should still be the same as Policy one's, i.e. not replaced
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.ManagedRules, policyOneStatic.Policy.Properties.ManagedRules))
	// generated Policy's Managed rules should still be different from Policy two's
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.ManagedRules, policyTwoStatic.Policy.Properties.ManagedRules))
}

func TestGeneratePolicyToRestoreBackupManagedOnly(t *testing.T) {
	policyOne, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwo, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyOneStatic, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwoStatic, err := LoadWrappedPolicyFromFile("../testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that providing two Policies (with both different Custom rules and Managed rules) with option to only replace
	// Custom rules with backup's Custom rules
	generatedPolicyThree := GeneratePolicyToRestore(&policyOne, &policyTwo, &RestorePoliciesInput{
		ManagedRulesOnly: true,
	})

	require.NotNil(t, generatedPolicyThree)
	// generated Policy's Custom rules should be identical to Policy one's
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.CustomRules, policyOneStatic.Policy.Properties.CustomRules))
	// generated Policy's Custom rules should be different from Policy two's Custom rules
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.CustomRules, policyTwoStatic.Policy.Properties.CustomRules))
	// generated Policy's Managed rules should be the same as Policy two's, i.e. replaced
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.ManagedRules, policyTwoStatic.Policy.Properties.ManagedRules))
	// generated Policy's Managed rules should be different from Policy one's
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.Properties.ManagedRules, policyOneStatic.Policy.Properties.ManagedRules))
}
