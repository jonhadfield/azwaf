package policy

import (
	"fmt"
	"github.com/jonhadfield/azwaf/config"
	"github.com/stretchr/testify/require"
	"regexp"
	"testing"
)

func TestDeleteCustomRuleNoCustomRules(t *testing.T) {
	policyOne, err := LoadPolicyFromFile("testdata/test-policy-four.json")
	require.NoError(t, err)

	modified, err := DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
		Policy:      &policyOne,
		RID:         config.ResourceID{},
		Name:        *policyOne.Name,
		NameMatch:   nil,
		Priority:    0,
		PrioritySet: false,
		MaxRules:    0,
		Debug:       false,
	})

	require.NoError(t, err)
	require.False(t, modified)
}

func TestDeleteCustomRuleByPriority(t *testing.T) {
	policyOne, err := LoadPolicyFromFile("testdata/test-policy-three.json")

	require.NoError(t, err)
	fmt.Println(len(policyOne.Properties.CustomRules.Rules))
	preNumRules := len(policyOne.Properties.CustomRules.Rules)

	modified, err := DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
		Policy:      &policyOne,
		RID:         config.ResourceID{},
		Name:        *policyOne.Name,
		NameMatch:   nil,
		Priority:    150,
		PrioritySet: true,
		MaxRules:    0,
		Debug:       false,
	})

	require.NoError(t, err)
	require.True(t, modified)
	require.Len(t, policyOne.Properties.CustomRules.Rules, preNumRules-1)
}

func TestDeleteCustomRuleByNamePrefix(t *testing.T) {
	policyOne, err := LoadPolicyFromFile("testdata/test-policy-three.json")
	require.NoError(t, err)

	preNumRules := len(policyOne.Properties.CustomRules.Rules)

	modified, err := DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
		Policy:      &policyOne,
		RID:         config.ResourceID{},
		Name:        *policyOne.Name,
		NameMatch:   regexp.MustCompile("^RateLimitIPs"),
		Priority:    0,
		PrioritySet: false,
		MaxRules:    0,
		Debug:       false,
	})

	require.NoError(t, err)
	require.True(t, modified)
	require.Len(t, policyOne.Properties.CustomRules.Rules, preNumRules-1)
}

func TestDeleteCustomRuleByPriorityAndNamePrefix(t *testing.T) {
	policyOne, err := LoadPolicyFromFile("testdata/test-policy-three.json")
	require.NoError(t, err)

	preNumRules := len(policyOne.Properties.CustomRules.Rules)

	modified, err := DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
		Policy:      &policyOne,
		RID:         config.ResourceID{},
		Name:        *policyOne.Name,
		NameMatch:   regexp.MustCompile("^RateLimitIPs"),
		Priority:    150,
		PrioritySet: true,
		MaxRules:    0,
		Debug:       false,
	})

	require.NoError(t, err)
	require.True(t, modified)
	require.Len(t, policyOne.Properties.CustomRules.Rules, preNumRules-1)
}

func TestDeleteCustomRuleByPriorityAndNamePrefixNoMatchPriority(t *testing.T) {
	policyOne, err := LoadPolicyFromFile("testdata/test-policy-three.json")

	require.NoError(t, err)
	modified, err := DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
		Policy:      &policyOne,
		RID:         config.ResourceID{},
		Name:        *policyOne.Name,
		NameMatch:   regexp.MustCompile("^RateLimitIPs"),
		Priority:    149,
		PrioritySet: true,
		MaxRules:    0,
		Debug:       false,
	})

	require.NoError(t, err)
	require.False(t, modified)
	// require.Len(t, updatedPolicy.Properties.CustomRules.Rules, len(policyOne.Properties.CustomRules.Rules)-1)
}

func TestDeleteCustomRuleByPriorityAndNamePrefixNoMatchPrefix(t *testing.T) {
	policyOne, err := LoadPolicyFromFile("testdata/test-policy-three.json")

	require.NoError(t, err)
	fmt.Println(len(policyOne.Properties.CustomRules.Rules))
	modified, err := DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
		Policy:      &policyOne,
		RID:         config.ResourceID{},
		Name:        *policyOne.Name,
		NameMatch:   regexp.MustCompile("^Wibble"),
		Priority:    150,
		PrioritySet: true,
		MaxRules:    0,
		Debug:       false,
	})

	require.NoError(t, err)
	require.False(t, modified)
}

//
// func TestDeleteCustomRuleByPriorityAndNamePrefix(t *testing.T) {
// 	policyOne, err := LoadPolicyFromFile("testdata/test-policy-four.json")
// 	require.NoError(t, err)
//
// 	updatedPolicy, modified, err := DeleteCustomRulesPrefixes(DeleteCustomRulesPrefixesInput{
// 		Policy:      policyOne,
// 		RID:         config.ResourceID{},
// 		Name:        *policyOne.Name,
// 		NameMatch:   nil,
// 		Priority:    0,
// 		PrioritySet: false,
// 		MaxRules:    0,
// 		Debug:       false,
// 	})
//
// 	require.NoError(t, err)
// 	require.False(t, modified)
// 	require.Nil(t, updatedPolicy)
// }
