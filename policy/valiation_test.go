package policy

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceIDValidation(t *testing.T) {
	require.NoError(t, ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false))

	validateEmptyResource := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false)

	require.Error(t, validateEmptyResource)
	require.Contains(t, validateEmptyResource.Error(), "number of sections")

	validateInvalidFormatNonExtended := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/fly|ing/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false)

	require.Error(t, validateInvalidFormatNonExtended)
	require.Contains(t, validateInvalidFormatNonExtended.Error(), "format")

	validateInvalidFormatExtended := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", true)

	require.Error(t, validateInvalidFormatExtended)
	require.Contains(t, validateInvalidFormatExtended.Error(), "extended")

	validateFormatExtended := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy|test", true)

	require.NoError(t, validateFormatExtended)

	validateInvalidSection := ValidateResourceID("/sub/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false)

	require.Error(t, validateInvalidSection)
	require.Contains(t, validateInvalidSection.Error(), "resource id has invalid format")
}

func TestValidateResourceIDs(t *testing.T) {
	idOne := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/volcanos"
	idTwo := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/spaghetti/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/noodles"
	idThree := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/monster/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/pirates"
	idFour := "/subs/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/monster/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/pirates"

	require.NoError(t, ValidateResourceIDs([]string{idOne}))
	require.NoError(t, ValidateResourceIDs([]string{idOne, idThree}))
	require.Error(t, ValidateResourceIDs([]string{idTwo, idThree}))
	require.Error(t, ValidateResourceIDs([]string{idTwo}))
	require.Error(t, ValidateResourceIDs([]string{idFour}))
}

func TestMatchValuesHasMatchAll(t *testing.T) {
	ipwpi := ipMatchValuesWithPublicInternet()
	ipnpi := ipMatchValuesNoPublicInternet()

	res := MatchValuesHasMatchAll(ipwpi, "RemoteAddr", "IPMatch")
	require.True(t, res)
	res = MatchValuesHasMatchAll(ipnpi, "RemoteAddr", "IPMatch")
	require.False(t, res)
}

// Condition 1: negative match for specific ips
func TestCustomRuleHasDefaultDenyFive(t *testing.T) {
	ipnpi := ipMatchValuesNoPublicInternet()
	oipm := armfrontdoor.OperatorIPMatch
	mvra := armfrontdoor.MatchVariableRemoteAddr
	crese := armfrontdoor.CustomRuleEnabledStateEnabled
	crrtmr := armfrontdoor.RuleTypeMatchRule
	atb := armfrontdoor.ActionTypeBlock

	mcSet := []*armfrontdoor.MatchCondition{{
		MatchVariable:   &mvra,
		Operator:        &oipm,
		NegateCondition: BoolToPointer(true),
		MatchValue:      ipnpi,
	}}

	dd := CustomRuleHasDefaultDeny(&armfrontdoor.CustomRule{
		Name:            StrToPointer("CustomRuleWithDefaultDeny"),
		Priority:        Int32ToPointer(1),
		EnabledState:    &crese,
		RuleType:        &crrtmr,
		MatchConditions: mcSet,
		Action:          &atb,
	})
	require.True(t, dd)
}

// Block Rule where only condition has public internet match should result in default deny
func TestCustomRuleHasDefaultDenyOne(t *testing.T) {
	// mcSet1 matches a default deny (blocks anything as 0.0.0.0/0 is a match)
	mvrara := armfrontdoor.MatchVariableRemoteAddr
	mvra := armfrontdoor.OperatorIPMatch
	mcSet1 := []*armfrontdoor.MatchCondition{{
		MatchVariable:   &mvrara,
		Operator:        &mvra,
		NegateCondition: BoolToPointer(false),
		MatchValue:      ipMatchValuesWithPublicInternet(),
	}}

	crese := armfrontdoor.CustomRuleEnabledStateEnabled
	crrtmr := armfrontdoor.RuleTypeMatchRule
	atb := armfrontdoor.ActionTypeBlock
	dd := CustomRuleHasDefaultDeny(&armfrontdoor.CustomRule{
		Name:            StrToPointer("CustomRuleWithDefaultDeny"),
		Priority:        Int32ToPointer(1),
		EnabledState:    &crese,
		RuleType:        &crrtmr,
		MatchConditions: mcSet1,

		Action: &atb,
	})
	require.True(t, dd)
}

// Block Rule with two conditions
// Condition 1: public internet match (positive match for 0.0.0.0/0)
// Condition 2: public internet match (negative match for specific ranges)
func TestCustomRuleHasDefaultDenyTwo(t *testing.T) {
	ipwpi := ipMatchValuesWithPublicInternet()
	ipnpi := ipMatchValuesNoPublicInternet()
	oipm := armfrontdoor.OperatorIPMatch
	mvra := armfrontdoor.MatchVariableRemoteAddr
	crese := armfrontdoor.CustomRuleEnabledStateEnabled
	crrtmr := armfrontdoor.RuleTypeMatchRule
	atb := armfrontdoor.ActionTypeBlock

	// mcSet1 matches a default deny (blocks anything as 0.0.0.0/0 is a match)
	mc1 := armfrontdoor.MatchCondition{
		MatchVariable:   &mvra,
		Operator:        &oipm,
		NegateCondition: BoolToPointer(false),
		MatchValue:      ipwpi,
		Transforms:      nil,
	}

	mc2 := armfrontdoor.MatchCondition{
		MatchVariable:   &mvra,
		Operator:        &oipm,
		NegateCondition: BoolToPointer(true),
		MatchValue:      ipnpi,
	}

	mcSet := []*armfrontdoor.MatchCondition{&mc1, &mc2}

	dd := CustomRuleHasDefaultDeny(&armfrontdoor.CustomRule{
		Name:            StrToPointer("CustomRuleWithDefaultDeny"),
		Priority:        Int32ToPointer(1),
		EnabledState:    &crese,
		RuleType:        &crrtmr,
		MatchConditions: mcSet,
		Action:          &atb,
		// Action:          "Block",
	})
	require.True(t, dd)
}

// Block Rule with one condition
// Condition 1: positive match for specific ranges
func TestCustomRuleHasDefaultDenyThree(t *testing.T) {
	oipm := armfrontdoor.OperatorIPMatch
	mvra := armfrontdoor.MatchVariableRemoteAddr
	ipnpi := ipMatchValuesNoPublicInternet()
	crese := armfrontdoor.CustomRuleEnabledStateEnabled
	crrtmr := armfrontdoor.RuleTypeMatchRule
	atb := armfrontdoor.ActionTypeBlock

	mcSet := []*armfrontdoor.MatchCondition{{
		MatchVariable:   &mvra,
		Selector:        nil,
		Operator:        &oipm,
		NegateCondition: BoolToPointer(false),
		MatchValue:      ipnpi,
		Transforms:      nil,
	}}

	dd := CustomRuleHasDefaultDeny(&armfrontdoor.CustomRule{
		Name:            StrToPointer("CustomRuleWithDefaultDeny"),
		Priority:        Int32ToPointer(1),
		EnabledState:    &crese,
		RuleType:        &crrtmr,
		MatchConditions: mcSet,
		Action:          &atb,
	})
	require.False(t, dd)
}

// Condition 1: negative match for public internet (matches everything)
func TestCustomRuleHasDefaultDenyFour(t *testing.T) {
	ipwpi := ipMatchValuesWithPublicInternet()
	oipm := armfrontdoor.OperatorIPMatch
	mvra := armfrontdoor.MatchVariableRemoteAddr
	crese := armfrontdoor.CustomRuleEnabledStateEnabled
	crrtmr := armfrontdoor.RuleTypeMatchRule
	atb := armfrontdoor.ActionTypeBlock

	mcSet := []*armfrontdoor.MatchCondition{{
		MatchVariable:   &mvra,
		Operator:        &oipm,
		NegateCondition: BoolToPointer(true),
		MatchValue:      ipwpi,
	}}

	dd := CustomRuleHasDefaultDeny(&armfrontdoor.CustomRule{
		Name:            StrToPointer("CustomRuleWithDefaultDeny"),
		Priority:        Int32ToPointer(1),
		EnabledState:    &crese,
		RuleType:        &crrtmr,
		MatchConditions: mcSet,
		Action:          &atb,
	})
	require.False(t, dd)
}
