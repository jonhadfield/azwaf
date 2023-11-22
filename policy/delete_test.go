package policy

import (
	"regexp"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func int32ptr(i int) *int32 {
	i32 := int32(i)
	return &i32
}

func getTestCRsSetOne() []*armfrontdoor.CustomRule {
	aBlock := armfrontdoor.ActionTypeBlock

	return []*armfrontdoor.CustomRule{
		{
			Action:   &aBlock,
			Priority: int32ptr(0),
			Name:     StrToPointer("crZero"),
		},
		{
			Action:   &aBlock,
			Priority: int32ptr(1),
			Name:     StrToPointer("crOne"),
		},
		{
			Action:   &aBlock,
			Priority: int32ptr(2),
			Name:     StrToPointer("crTwo"),
		},
	}
}

func TestStripCRsMatchingNameRegex(t *testing.T) {
	res := stripCustomRulesMatchingNameOrPriority(false, 0, regexp.MustCompile(`^cr.+o$`), getTestCRsSetOne())
	require.Len(t, res, 1)
	require.NotNil(t, res[0].Name)
	require.Equal(t, "crOne", *res[0].Name)
}

func TestStripCRsMatchingPriority(t *testing.T) {
	res := stripCustomRulesMatchingNameOrPriority(true, 0, nil, getTestCRsSetOne())
	require.Len(t, res, 2)
	require.NotNil(t, res[0].Name)
	require.Equal(t, "crOne", *res[0].Name)
	require.Equal(t, int32(1), *res[0].Priority)
	require.NotNil(t, res[1].Name)
	require.Equal(t, "crTwo", *res[1].Name)
	require.Equal(t, int32(2), *res[1].Priority)
}

func TestStripCRsMatchingNameAndPriority(t *testing.T) {
	res := stripCustomRulesMatchingNameOrPriority(true, 1, regexp.MustCompile(`^cr.+$`), getTestCRsSetOne())
	require.Len(t, res, 2)
	require.NotNil(t, res[0].Name)
	require.Equal(t, "crZero", *res[0].Name)
	require.Equal(t, "crTwo", *res[1].Name)
	require.Equal(t, int32(0), *res[0].Priority)
	require.Equal(t, int32(2), *res[1].Priority)
}

// func getTestManagedRuleOverrideOne() *armfrontdoor.ManagedRuleOverride {
//	// rule one
//	action := armfrontdoor.ActionType("Block")
//	state := armfrontdoor.ManagedRuleEnabledState("Enabled")
//	// - exclusion
//	matchVariable := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestBodyPostArgNames")
//	matchOperator := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("Contains")
//	matchSelector := StrToPointer("Cheese")
//
//	return &armfrontdoor.ManagedRuleOverride{
//		RuleID:       StrToPointer("265220"),
//		Action:       &action,
//		EnabledState: &state,
//		Exclusions: []*armfrontdoor.ManagedRuleExclusion{
//			{
//				MatchVariable:         &matchVariable,
//				Selector:              matchSelector,
//				SelectorMatchOperator: &matchOperator,
//			},
//		},
//	}
// }
//
// // exclusionRuleOperator: "Equals",
// //
// //	exclusionRuleVariable: "QueryStringArgNames",
// //	exclusionRuleSelector: "Vegetable",
// //	Scope:                 ScopeRuleSet,
// //	Debug:                 true,
// func getTestManagedRuleOverrideTwo() *armfrontdoor.ManagedRuleOverride {
//	// rule two
//	action := armfrontdoor.ActionType("Log")
//	state := armfrontdoor.ManagedRuleEnabledState("Disabled")
//	// - exclusion one
//	matchVariable1 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestHeaderNames")
//	matchOperator1 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("EndsWith")
//	matchSelector1 := StrToPointer("Toast")
//	// - exclusion two
//	matchVariable2 := armfrontdoor.ManagedRuleExclusionMatchVariable("QueryStringArgNames")
//	matchOperator2 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("Equals")
//	matchSelector2 := StrToPointer("Vegetable")
//
//	return &armfrontdoor.ManagedRuleOverride{
//		RuleID:       StrToPointer("265221"),
//		Action:       &action,
//		EnabledState: &state,
//		Exclusions: []*armfrontdoor.ManagedRuleExclusion{
//			{
//				MatchVariable:         &matchVariable1,
//				Selector:              matchSelector1,
//				SelectorMatchOperator: &matchOperator1,
//			},
//			{
//				MatchVariable:         &matchVariable2,
//				Selector:              matchSelector2,
//				SelectorMatchOperator: &matchOperator2,
//			},
//		},
//	}
// }

func TestStripMatchingMREs(t *testing.T) {
	ruleSetOne := getTestRuleSetOne()
	ruleSetTwo := getTestRuleSetTwo()

	require.Len(t, ruleSetOne.RuleGroupOverrides, 1)
	require.Len(t, ruleSetOne.RuleGroupOverrides[0].Exclusions, 3)
	require.Len(t, ruleSetTwo.RuleGroupOverrides, 1)
	require.Len(t, ruleSetTwo.RuleGroupOverrides[0].Exclusions, 3)

	updatedRuleSets, err := stripMatchingMREs(&DeleteManagedRuleExclusionInput{
		DryRun:                false,
		RuleGroup:             "JAVA",
		ExclusionRuleVariable: "RequestCookieNames",
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleSelector: "all",
		Scope:                 ScopeRuleGroup,
	}, &armfrontdoor.ManagedRuleSetList{
		ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{&ruleSetOne, &ruleSetTwo},
	},
	)
	require.NoError(t, err)
	require.Len(t, updatedRuleSets.ManagedRuleSets, 2)
	require.Len(t, updatedRuleSets.ManagedRuleSets[0].RuleGroupOverrides, 1)
	require.Len(t, updatedRuleSets.ManagedRuleSets[0].RuleGroupOverrides[0].Exclusions, 2)
	require.Len(t, updatedRuleSets.ManagedRuleSets[1].RuleGroupOverrides, 1)
	require.Len(t, updatedRuleSets.ManagedRuleSets[1].RuleGroupOverrides[0].Exclusions, 3)
}

func TestStripManagedRuleGroupOverrideRules(t *testing.T) {
	emrgo := getTestManagedGroupOverridesOne()

	newOverrides := stripManagedRuleGroupOverrideRules(&DeleteManagedRuleExclusionInput{
		ExclusionRuleVariable: "RequestBodyPostArgNames",
		ExclusionRuleOperator: "Contains",
		ExclusionRuleSelector: "Cheese",
	}, emrgo)
	require.Len(t, newOverrides, 2)
	require.Len(t, newOverrides[0].Exclusions, 0)
	require.Len(t, newOverrides[1].Exclusions, 2)
}

func TestMatchManagedRuleGroupOverrideExclusionPositive(t *testing.T) {
	emrgo := getTestExclusionsOne()
	res := matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
		existingManagedRuleExclusion: emrgo[1],
		variable:                     "RequestBodyPostArgNames",
		operator:                     "StartsWith",
		selector:                     "Your",
	})
	require.True(t, res)
}

func TestMatchManagedRuleGroupOverrideExclusionNegative(t *testing.T) {
	emrgo := getTestExclusionsOne()
	res := matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
		existingManagedRuleExclusion: emrgo[1],
		variable:                     "RequestCookieNames",
		operator:                     "StartsWith",
		selector:                     "Your",
	})
	require.False(t, res)
}

func TestMatchManagedRuleGroupOverrideExclusionEmptyInput(t *testing.T) {
	res := matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
		existingManagedRuleExclusion: &armfrontdoor.ManagedRuleExclusion{},
		variable:                     "RequestCookieNames",
		operator:                     "StartsWith",
		selector:                     "Your",
	})
	require.False(t, res)
}

//
// func TestMatchManagedRuleGroupOverrideExclusionMissingSelector(t *testing.T) {
//	mremv := armfrontdoor.ManagedRuleExclusionMatchVariable("a")
//	mrems := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("b")
//	res, _ := matchManagedRuleGroupOverrideExclusion()
//	require.False(t, res)
// }
//
// func TestStripManagedRuleOverrideNegativeMatchRuleID(t *testing.T) {
//	dcri := DeleteManagedRuleExclusionInput{
//		RuleID: "cheese",
//	}
//	mro := stripManagedRuleOverride(dcri, &armfrontdoor.ManagedRuleOverride{
//		RuleID: StrToPointer("vegetable"),
//	})
//
//	require.Equal(t, "vegetable", *mro.RuleID)
// }

func TestStripManagedRuleOverridePositiveMatch(t *testing.T) {
	dcri := &DeleteManagedRuleExclusionInput{
		RuleID: "cheese",
	}

	mv1 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestCookieNames")
	mo1 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("EndsWith")
	mv2 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestHeaderNames")
	mo2 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("Contains")
	mro := stripManagedRuleOverride(dcri, &armfrontdoor.ManagedRuleOverride{
		RuleID: StrToPointer("cheese"),
		Exclusions: []*armfrontdoor.ManagedRuleExclusion{
			{
				MatchVariable:         &mv1,
				Selector:              StrToPointer("sel1"),
				SelectorMatchOperator: &mo1,
			},
			{
				MatchVariable:         &mv2,
				Selector:              StrToPointer("sel2"),
				SelectorMatchOperator: &mo2,
			},
		},
	})

	require.NotNil(t, mro)
	require.Empty(t, mro.Exclusions)
}

func TestStripManagedRuleOverrideExclusionsPositiveMatch(t *testing.T) {
	dcri := &DeleteManagedRuleExclusionInput{
		RuleID:                "cheese",
		ExclusionRuleVariable: "QueryStringArgNames",
		ExclusionRuleOperator: "StartsWith",
		ExclusionRuleSelector: "vegetable",
	}

	mv1 := armfrontdoor.ManagedRuleExclusionMatchVariable("QueryStringArgNames")
	mo1 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("Equals")
	mv2 := armfrontdoor.ManagedRuleExclusionMatchVariable("QueryStringArgNames")
	mo2 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("StartsWith")

	mro := stripManagedRuleOverride(dcri, &armfrontdoor.ManagedRuleOverride{
		RuleID: StrToPointer("cheese"),
		Exclusions: []*armfrontdoor.ManagedRuleExclusion{
			{
				MatchVariable:         &mv1,
				Selector:              StrToPointer("fromage"),
				SelectorMatchOperator: &mo1,
			},
			{
				MatchVariable:         &mv2,
				Selector:              StrToPointer("vegetable"),
				SelectorMatchOperator: &mo2,
			},
		},
	})

	require.NotNil(t, mro)
	require.Len(t, mro.Exclusions, 1)
	require.Equal(t, "fromage", *mro.Exclusions[0].Selector)
}

//	func stripManagedRuleGroupOverrideExclusions(dcri policy.DeleteManagedRuleExclusionInput, existingManagedRuleExclusions []*armfrontdoor.ManagedRuleExclusion) (newManagedRuleExclusions []*armfrontdoor.ManagedRuleExclusion) {
//		if dcri.exclusionRuleOperator == "" || dcri.exclusionRuleSelector == "" || dcri.exclusionRuleVariable == "" {
//			return nil
//		}
//		for _, managedRuleExclusion := range existingManagedRuleExclusions {
//			if !matchManagedRuleGroupOverrideExclusion(dcri, managedRuleExclusion) {
//				newManagedRuleExclusions = append(newManagedRuleExclusions, managedRuleExclusion)
//			}
//		}
//
//		if len(newManagedRuleExclusions) != 0 {
//			return newManagedRuleExclusions
//		}
//
//		return nil
//	}
func TestStripManagedRuleGroupOverrideExclusions(t *testing.T) {
	dcri := &DeleteManagedRuleExclusionInput{
		ExclusionRuleOperator: "StartsWith",
		ExclusionRuleVariable: "RequestCookieNames",
		ExclusionRuleSelector: "cheese",
	}

	mremv1 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestCookieNames")
	mres1 := "cheese"
	mresmo1 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("StartsWith")

	mremv2 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestBodyPostArgNames")
	mres2 := "fromage"
	mresmo2 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("EndsWith")

	existingMREs := []*armfrontdoor.ManagedRuleExclusion{
		{
			MatchVariable:         &mremv1,
			Selector:              &mres1,
			SelectorMatchOperator: &mresmo1,
		},
		{
			MatchVariable:         &mremv2,
			Selector:              &mres2,
			SelectorMatchOperator: &mresmo2,
		},
	}

	managedRuleGroupOverrideExclusions := stripManagedRuleGroupOverrideExclusions(dcri, existingMREs)
	require.Len(t, managedRuleGroupOverrideExclusions, 1)
}

func TestGetDeleteManagedRuleExclusionProcessScope(t *testing.T) {
	scope, err := GetDeleteManagedRuleExclusionProcessScope(&DeleteManagedRuleExclusionInput{
		RuleSetType:    StrToPointer("test"),
		RuleSetVersion: StrToPointer("set"),
	})
	require.NoError(t, err)
	require.Equal(t, ScopeRuleSet, scope)
	scope, err = GetDeleteManagedRuleExclusionProcessScope(&DeleteManagedRuleExclusionInput{
		RuleSetType:    StrToPointer("test"),
		RuleSetVersion: StrToPointer("set"),
		RuleGroup:      "test group",
	})
	require.NoError(t, err)
	require.Equal(t, ScopeRuleGroup, scope)

	scope, err = GetDeleteManagedRuleExclusionProcessScope(&DeleteManagedRuleExclusionInput{
		RuleID: "test rule id",
	})
	require.NoError(t, err)
	require.Equal(t, ScopeRule, scope)
}

// var ValidRuleExclusionMatchVariables = [...]string{
//	"RequestCookieNames",
//	"RequestHeaderNames",
//	"QueryStringArgNames",
//	"RequestBodyPostArgNames",
//	"RequestBodyJsonArgNames",
// }
//
// var ValidRuleExclusionMatchOperators = [...]string{
//	"Contains",
//	"EndsWith",
//	"Equals",
//	"EqualsAny",
//	"StartsWith",
// }

func TestStripManagedRuleOverrideExckusionsPositiveMatch(t *testing.T) {
	dcri := &DeleteManagedRuleExclusionInput{
		RuleID:                "cheese",
		ExclusionRuleVariable: "RequestBodyPostArgNames",
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleSelector: "sel2",
	}

	mv1 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestCookieName")
	mo1 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("EndsWith")
	mv2 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestBodyPostArgNames")
	mo2 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("EndsWith")

	mro := stripManagedRuleOverride(dcri, &armfrontdoor.ManagedRuleOverride{
		RuleID: StrToPointer("cheese"),
		Exclusions: []*armfrontdoor.ManagedRuleExclusion{
			{
				MatchVariable:         &mv1,
				Selector:              StrToPointer("sel1"),
				SelectorMatchOperator: &mo1,
			},
			{
				MatchVariable:         &mv2,
				Selector:              StrToPointer("sel2"),
				SelectorMatchOperator: &mo2,
			},
		},
	})

	require.NotNil(t, mro)
	require.Len(t, mro.Exclusions, 1)
	require.Equal(t, "sel1", *mro.Exclusions[0].Selector)
}

// func stripFromManagedRuleSet(dcri DeleteManagedRuleExclusionInput, RuleSets *armfrontdoor.ManagedRuleSet) (newMRS *armfrontdoor.ManagedRuleSet, err error) {
//	newMRS = &armfrontdoor.ManagedRuleSet{}
//	// get stripped RuleGroupOverrides
//	for _, existingManagedRuleGroupOverride := range RuleSets.RuleGroupOverrides {
//		logrus.Debugf("RuleGroupOverride: %s", *existingManagedRuleGroupOverride.RuleGroupName)
//		var strippedManagedRuleGroupOverride *armfrontdoor.ManagedRuleGroupOverride
//		strippedManagedRuleGroupOverride, err = stripManagedRuleGroupOverride(dcri, existingManagedRuleGroupOverride)
//		if err != nil {
//			return nil, fmt.Errorf("stripFromManagedRuleSet | %w", err)
//		}
//
//		newMRS.RuleGroupOverrides = append(newMRS.RuleGroupOverrides, strippedManagedRuleGroupOverride)
//	}
//
//	logrus.Debugf("stripFromManagedRuleSet | started with %d rule group overrides and returning %d for ruleset %s_%s", len(RuleSets.RuleGroupOverrides), len(newMRS.RuleGroupOverrides), *RuleSets.RuleSetType, *RuleSets.RuleSetVersion)
//
//	// if only rule set passed then process ruleset exclusions
//	if GetDeleteManagedRuleExclusionProcessScope(dcri) == ScopeRuleSet {
//		if !exclusionParamsDefined(dcri) {
//			return nil, errors.New("refusing to delete all exclusions")
//		}
//		for _, existingManagedRuleSetExclusion := range RuleSets.Exclusions {
//			var strippedManagedRuleGroupExclusion *armfrontdoor.ManagedRuleExclusion
//			if !matchManagedRuleGroupOverrideExclusion(dcri, existingManagedRuleSetExclusion) {
//				newMRS.Exclusions = append(newMRS.Exclusions, strippedManagedRuleGroupExclusion)
//			}
//		}
//	} else {
//		newMRS.Exclusions = RuleSets.Exclusions
//	}
//
//	newMRS.RuleSetType = RuleSets.RuleSetType
//	newMRS.RuleSetVersion = RuleSets.RuleSetVersion
//
//	logrus.Debugf("stripFromManagedRuleSet | started with %d rule group Managed exclusions and returning %d for ruleset %s_%s", len(RuleSets.Exclusions), len(newMRS.Exclusions), *RuleSets.RuleSetType, *RuleSets.RuleSetVersion)
//
//	return
// }

func getTestManagedGroupOverridesOne() []*armfrontdoor.ManagedRuleOverride {
	return []*armfrontdoor.ManagedRuleOverride{
		getTestManagedRuleOverrideOne(),
		getTestManagedRuleOverrideTwo(),
	}
}

func getTestManagedGroupOverridesTwo() []*armfrontdoor.ManagedRuleOverride {
	return []*armfrontdoor.ManagedRuleOverride{
		getTestManagedRuleOverrideOne(),
		getTestManagedRuleOverrideTwo(),
	}
}

func getTestManagedRuleOverrideOne() *armfrontdoor.ManagedRuleOverride {
	// rule one
	action := armfrontdoor.ActionType("Block")
	state := armfrontdoor.ManagedRuleEnabledState("Enabled")
	// - exclusion
	matchVariable := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestBodyPostArgNames")
	matchOperator := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("Contains")
	matchSelector := StrToPointer("Cheese")

	return &armfrontdoor.ManagedRuleOverride{
		RuleID:       StrToPointer("265220"),
		Action:       &action,
		EnabledState: &state,
		Exclusions: []*armfrontdoor.ManagedRuleExclusion{
			{
				MatchVariable:         &matchVariable,
				Selector:              matchSelector,
				SelectorMatchOperator: &matchOperator,
			},
		},
	}
}

// exclusionRuleOperator: "Equals",
//
//	exclusionRuleVariable: "QueryStringArgNames",
//	exclusionRuleSelector: "Vegetable",
//	Scope:                 ScopeRuleSet,
//	Debug:                 true,
func getTestManagedRuleOverrideTwo() *armfrontdoor.ManagedRuleOverride {
	// rule two
	action := armfrontdoor.ActionType("Log")
	state := armfrontdoor.ManagedRuleEnabledState("Disabled")
	// - exclusion one
	matchVariable1 := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestHeaderNames")
	matchOperator1 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("EndsWith")
	matchSelector1 := StrToPointer("Toast")
	// - exclusion two
	matchVariable2 := armfrontdoor.ManagedRuleExclusionMatchVariable("QueryStringArgNames")
	matchOperator2 := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("Equals")
	matchSelector2 := StrToPointer("Vegetable")

	return &armfrontdoor.ManagedRuleOverride{
		RuleID:       StrToPointer("265221"),
		Action:       &action,
		EnabledState: &state,
		Exclusions: []*armfrontdoor.ManagedRuleExclusion{
			{
				MatchVariable:         &matchVariable1,
				Selector:              matchSelector1,
				SelectorMatchOperator: &matchOperator1,
			},
			{
				MatchVariable:         &matchVariable2,
				Selector:              matchSelector2,
				SelectorMatchOperator: &matchOperator2,
			},
		},
	}
}

func getManagedRuleGroupOverrideOne() *armfrontdoor.ManagedRuleGroupOverride {
	return &armfrontdoor.ManagedRuleGroupOverride{
		RuleGroupName: StrToPointer("JAVA"),
		Exclusions:    getTestExclusionsTwo(),
		Rules:         getTestManagedGroupOverridesOne(),
	}
}

func getManagedRuleGroupOverrideTwo() *armfrontdoor.ManagedRuleGroupOverride {
	return &armfrontdoor.ManagedRuleGroupOverride{
		RuleGroupName: StrToPointer("PHP"),
		Exclusions:    getTestExclusionsTwo(),
		Rules:         getTestManagedGroupOverridesOne(),
	}
}

func getTestRuleSetOne() armfrontdoor.ManagedRuleSet {
	return armfrontdoor.ManagedRuleSet{
		RuleSetType:        StrToPointer("Microsoft_DefaultRuleSet"),
		RuleSetVersion:     StrToPointer("1.1"),
		Exclusions:         getTestExclusionsOne(),
		RuleGroupOverrides: []*armfrontdoor.ManagedRuleGroupOverride{getManagedRuleGroupOverrideOne()},
		RuleSetAction:      nil,
	}
}

func getTestRuleSetTwo() armfrontdoor.ManagedRuleSet {
	return armfrontdoor.ManagedRuleSet{
		RuleSetType:        StrToPointer("Microsoft_BotManagerRuleSet"),
		RuleSetVersion:     StrToPointer("1.0"),
		Exclusions:         getTestExclusionsTwo(),
		RuleGroupOverrides: []*armfrontdoor.ManagedRuleGroupOverride{getManagedRuleGroupOverrideTwo()},
		RuleSetAction:      nil,
	}
}

// func getTestManagedRuleSets() []*armfrontdoor.ManagedRuleSet {
// 	rsOne := getTestRuleSetOne()
// 	return []*armfrontdoor.ManagedRuleSet{
// 		&rsOne,
// 	}
// }

//
// func getTestPolicyOne() armfrontdoor.WebApplicationFirewallPolicy {
// 	return armfrontdoor.WebApplicationFirewallPolicy{
// 		Etag:     StrToPointer("etag"),
// 		Location: StrToPointer("uksouth"),
// 		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
// 			CustomRules:           &armfrontdoor.CustomRuleList{Rules: getTestCRsSetOne()},
// 			ManagedRules:          &armfrontdoor.ManagedRuleSetList{ManagedRuleSets: getTestManagedRuleSets()},
// 			PolicySettings:        nil,
// 			FrontendEndpointLinks: nil,
// 			ProvisioningState:     nil,
// 			ResourceState:         nil,
// 			RoutingRuleLinks:      nil,
// 			SecurityPolicyLinks:   nil,
// 		},
// 		SKU:  nil,
// 		Tags: nil,
// 		ID:   nil,
// 		Name: nil,
// 		Type: nil,
// 	}
//
// }

func getTestExclusionsOne() []*armfrontdoor.ManagedRuleExclusion {
	reqHeaderNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames
	reqBodyPostArgNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestBodyPostArgNames
	reqCookieNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestCookieNames
	startsWith := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorStartsWith
	endsWith := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith
	contains := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorContains
	// exclusionRuleOperator: "Equals",
	//		exclusionRuleVariable: "QueryStringArgNames",
	//		exclusionRuleSelector: "Vegetable",
	return []*armfrontdoor.ManagedRuleExclusion{
		{
			MatchVariable:         &reqHeaderNames,
			Selector:              StrToPointer("Relax"),
			SelectorMatchOperator: &endsWith,
		},
		{
			MatchVariable:         &reqBodyPostArgNames,
			Selector:              StrToPointer("Your"),
			SelectorMatchOperator: &startsWith,
		},
		{
			MatchVariable:         &reqCookieNames,
			Selector:              StrToPointer("Eyes"),
			SelectorMatchOperator: &contains,
		},
	}
}

func getTestExclusionsTwo() []*armfrontdoor.ManagedRuleExclusion {
	reqHeaderNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames
	reqBodyPostArgNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestBodyPostArgNames
	reqCookieNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestCookieNames
	startsWith := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorStartsWith
	endsWith := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith
	contains := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorContains

	return []*armfrontdoor.ManagedRuleExclusion{
		{
			MatchVariable:         &reqHeaderNames,
			Selector:              StrToPointer("Al"),
			SelectorMatchOperator: &startsWith,
		},
		{
			MatchVariable:         &reqBodyPostArgNames,
			Selector:              StrToPointer("Knows"),
			SelectorMatchOperator: &contains,
		},
		{
			MatchVariable:         &reqCookieNames,
			Selector:              StrToPointer("all"),
			SelectorMatchOperator: &endsWith,
		},
	}
}

// func getTestExclusionsThree() []*armfrontdoor.ManagedRuleExclusion {
//	reqHeaderNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames
//	reqBodyPostArgNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestBodyPostArgNames
//	reqCookieNames := armfrontdoor.ManagedRuleExclusionMatchVariableRequestCookieNames
//	startsWith := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorStartsWith
//	endsWith := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith
//	contains := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorContains
//
//	return []*armfrontdoor.ManagedRuleExclusion{
//		{
//			MatchVariable:         &reqHeaderNames,
//			Selector:              StrToPointer("Loki"),
//			SelectorMatchOperator: &contains,
//		},
//		{
//			MatchVariable:         &reqBodyPostArgNames,
//			Selector:              StrToPointer("Loves"),
//			SelectorMatchOperator: &startsWith,
//		},
//		{
//			MatchVariable:         &reqCookieNames,
//			Selector:              StrToPointer("Chicken"),
//			SelectorMatchOperator: &endsWith,
//		},
//	}
// }

// func getTes

func TestStripFromManagedRuleGroup(t *testing.T) {
	newOverrides := stripManagedRuleGroupOverrideRules(&DeleteManagedRuleExclusionInput{
		ExclusionRuleVariable: "RequestHeaderNames",
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleSelector: "Toast",
		Debug:                 true,
	}, getTestManagedGroupOverridesOne())
	require.Len(t, newOverrides, 2)
	require.Len(t, newOverrides[0].Exclusions, 1)
	require.Len(t, newOverrides[1].Exclusions, 1)
}

func TestStripFromManagedRuleSet(t *testing.T) {
	mrs := getTestRuleSetOne()

	dcri := &DeleteManagedRuleExclusionInput{
		ExclusionRuleOperator: "Equals",
		ExclusionRuleVariable: "QueryStringArgNames",
		ExclusionRuleSelector: "Vegetable",
		Debug:                 true,
		Scope:                 ScopeRule,
	}
	sMrs, err := stripFromManagedRuleSet(dcri, &mrs)
	assert.Nil(t, err)
	assert.NotEmpty(t, sMrs)
	assert.Len(t, sMrs.RuleGroupOverrides, 1)
	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules, 2)
	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules[0].Exclusions, 1)
	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules[1].Exclusions, 1)
	assert.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].MatchVariable)
	assert.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].SelectorMatchOperator)
	assert.Equal(t, "Toast", *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].Selector)
}

func TestStripExclusionFromManagedRuleSet(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	mrs := getTestRuleSetOne()

	dcri := &DeleteManagedRuleExclusionInput{
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleVariable: "RequestHeaderNames",
		ExclusionRuleSelector: "Toast",
		Scope:                 ScopeRule,
		Debug:                 true,
	}

	sMrs, err := stripFromManagedRuleSet(dcri, &mrs)
	assert.Nil(t, err)
	assert.NotEmpty(t, sMrs)
	assert.Len(t, sMrs.RuleGroupOverrides, 1)
	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules, 2)
	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules[0].Exclusions, 1)
	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules[1].Exclusions, 1)
	assert.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableQueryStringArgNames,
		*sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].MatchVariable)

	assert.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEquals,
		*sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].SelectorMatchOperator)
	assert.Equal(t, "Vegetable", *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].Selector)
}

// action := armfrontdoor.ActionType("Block")
//	state := armfrontdoor.ManagedRuleEnabledState("Enabled")
//	matchVariable := armfrontdoor.ManagedRuleExclusionMatchVariable("RequestBodyPostArgNames")
//	matchOperator := armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("Contains")
//	matchSelector := StrToPointer("Cheese")
// func TestMatchManagedRuleGroupOverrideExclusion(t *testing.T) {
//	o := getTestManagedRuleOverrideOne()
//	//fmt.Println(matchManagedRuleGroupOverrideExclusion(DeleteManagedRuleExclusionInput{
//	//	exclusionRuleVariable: "RequestBodyPostArgNames",
//	//	exclusionRuleOperator: "contains",
//	//	exclusionRuleSelector: "bheese",
//	//	Debug:                 true,
//	//}, o.Exclusions[0]))
//
//	//fmt.Println(matchManagedRuleGroupOverrideExclusion(DeleteManagedRuleExclusionInput{
//	//	exclusionRuleVariable: "RequestBodyPostArgNames",
//	//	exclusionRuleOperator: "contains",
//	//	exclusionRuleSelector: "bheese",
//	//	Debug:                 true,
//	//}, o.Exclusions[0]))
//
//	// selector is always case-sensitive
//	mrgoe, err := matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
//		existingManagedRuleExclusion: o.Exclusions[0],
//		variable:                     "",
//		operator:                     "",
//		selector:                     "",
//	})
//	require.NoError(t, err)
//	require.False(t, mrgoe)
//	// variable and operator with mixed, non-standard case
//	mrgoe, err = matchManagedRuleGroupOverrideExclusion()
//	require.NoError(t, err)
//	require.True(t, mrgoe)
// }

//
// //
// func TestMatchManagedRuleGroupOverrideRule(t *testing.T) {
//	o := getTestManagedRuleOverrideOne()
//	//fmt.Println(matchManagedRuleGroupOverrideExclusion(DeleteManagedRuleExclusionInput{
//	//	exclusionRuleVariable: "RequestBodyPostArgNames",
//	//	exclusionRuleOperator: "contains",
//	//	exclusionRuleSelector: "bheese",
//	//	Debug:                 true,
//	//}, o.Exclusions[0]))
//
//	//fmt.Println(matchManagedRuleGroupOverrideExclusion(DeleteManagedRuleExclusionInput{
//	//	exclusionRuleVariable: "RequestBodyPostArgNames",
//	//	exclusionRuleOperator: "contains",
//	//	exclusionRuleSelector: "bheese",
//	//	Debug:                 true,
//	//}, o.Exclusions[0]))
//
//	// selector is always case-sensitive
//	mrgoe, err := matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
//		existingManagedRuleExclusion: nil,
//		variable:                     "",
//		operator:                     "",
//		selector:                     "",
//	})
//	require.NoError(t, err)
//	require.False(t, mrgoe)
//	// variable and operator with mixed, non-standard case
//	mrgoe, err = matchManagedRuleGroupOverrideExclusion()
//	require.NoError(t, err)
//	require.True(t, mrgoe)
// }

// func TestStripFromManagedRuleSetCaseInsensitive(t *testing.T) {
//	mrs := getTestRuleSetOne()
//
//	dcri := &DeleteManagedRuleExclusionInput{
//		exclusionRuleOperator: "equals",
//		exclusionRuleVariable: "querystringargNames",
//		exclusionRuleSelector: "Vegetable",
//		Debug:                 true,
//	}
//
//	sMrs, err := stripFromManagedRuleSet(dcri, &mrs)
//	assert.NoError(t, err)
//	assert.NotEmpty(t, sMrs)
//	assert.Len(t, sMrs.RuleGroupOverrides, 1)
//	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules, 2)
//	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules[0].Exclusions, 1)
//	assert.Len(t, sMrs.RuleGroupOverrides[0].Rules[1].Exclusions, 1)
//	assert.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].MatchVariable)
//	assert.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].SelectorMatchOperator)
//	assert.Equal(t, "Toast", *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].Selector)
// }

func TestStripFromManagedRuleGroupTwo(t *testing.T) {
	newOverrides := stripManagedRuleGroupOverrideRules(&DeleteManagedRuleExclusionInput{
		ExclusionRuleVariable: "RequestHeaderNames",
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleSelector: "Toast",
		Debug:                 true,
	}, getTestManagedGroupOverridesTwo())
	require.Len(t, newOverrides, 2)
	require.Len(t, newOverrides[0].Exclusions, 1)
	require.Len(t, newOverrides[1].Exclusions, 1)
}

func TestStripExclusionAtScopeRuleSet(t *testing.T) {
	mrs := getTestRuleSetOne()

	logrus.SetLevel(logrus.DebugLevel)

	dcri := &DeleteManagedRuleExclusionInput{
		ExclusionRuleOperator: "StartsWith",
		ExclusionRuleVariable: "RequestBodyPostArgNames",
		ExclusionRuleSelector: "Your",
		Scope:                 ScopeRuleSet,
		Debug:                 true,
	}

	sMrs, err := stripFromManagedRuleSet(dcri, &mrs)
	require.NoError(t, err)
	require.NotEmpty(t, sMrs)
	require.Len(t, sMrs.RuleGroupOverrides, 1)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules, 2)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules[0].Exclusions, 1)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].MatchVariable)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].SelectorMatchOperator)
	require.Equal(t, "Toast", *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].Selector)
	require.Len(t, sMrs.Exclusions, 2)
	require.Equal(t, "Relax", *sMrs.Exclusions[0].Selector)
	require.Equal(t, "Eyes", *sMrs.Exclusions[1].Selector)
}

func TestStripExclusionAtScopeRuleSetNoMatches(t *testing.T) {
	mrs := getTestRuleSetOne()

	logrus.SetLevel(logrus.DebugLevel)

	dcri := &DeleteManagedRuleExclusionInput{
		ExclusionRuleOperator: "StartsWith",
		ExclusionRuleVariable: "RequestBodyPostArgNames",
		ExclusionRuleSelector: "Elephant",
		Scope:                 ScopeRuleSet,
		Debug:                 true,
	}

	sMrs, err := stripFromManagedRuleSet(dcri, &mrs)
	require.NoError(t, err)
	require.NotEmpty(t, sMrs)
	//		{
	//			MatchVariable:         &reqBodyPostArgNames,
	//			Selector:              StrToPointer("Knows"),
	//			SelectorMatchOperator: &contains,
	//		},
	require.Len(t, sMrs.RuleGroupOverrides[0].Exclusions, 3)
	require.Equal(t, *sMrs.RuleGroupOverrides[0].Exclusions[0].Selector, "Al")
	require.Len(t, sMrs.RuleGroupOverrides, 1)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules, 2)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules[0].Exclusions, 1)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].MatchVariable)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].SelectorMatchOperator)
	require.Equal(t, "Toast", *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].Selector)
	require.Len(t, sMrs.Exclusions, 3)
	require.Equal(t, "Relax", *sMrs.Exclusions[0].Selector)
	require.Equal(t, "Your", *sMrs.Exclusions[1].Selector)
	require.Equal(t, "Eyes", *sMrs.Exclusions[2].Selector)
}

func TestStripExclusionAtScopeRuleGroup(t *testing.T) {
	mrs := getTestRuleSetOne()

	logrus.SetLevel(logrus.DebugLevel)

	dcri := &DeleteManagedRuleExclusionInput{
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleVariable: "RequestCookieNames",
		ExclusionRuleSelector: "all",
		RuleGroup:             "JAVA",
		Scope:                 ScopeRuleGroup,
		Debug:                 true,
	}
	// GROUP EXCLUSIONS
	// 		{
	//			MatchVariable:         &reqHeaderNames,
	//			Selector:              StrToPointer("Al"),
	//			SelectorMatchOperator: &startsWith,
	//		},
	//		{
	//			MatchVariable:         &reqBodyPostArgNames,
	//			Selector:              StrToPointer("Knows"),
	//			SelectorMatchOperator: &contains,
	//		},
	//		{
	//			MatchVariable:         &reqCookieNames,
	//			Selector:              StrToPointer("all"),
	//			SelectorMatchOperator: &endsWith,
	//		},

	sMrs, err := stripFromManagedRuleSet(dcri, &mrs)
	require.NoError(t, err)
	require.NotEmpty(t, sMrs)
	require.Len(t, sMrs.RuleGroupOverrides, 1)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules, 2)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules[0].Exclusions, 1)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].MatchVariable)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].SelectorMatchOperator)
	require.Equal(t, "Toast", *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].Selector)
	require.Len(t, sMrs.Exclusions, 3)
	require.Equal(t, "Relax", *sMrs.Exclusions[0].Selector)
	require.Equal(t, "Your", *sMrs.Exclusions[1].Selector)
	require.Equal(t, "Eyes", *sMrs.Exclusions[2].Selector)
	require.Len(t, sMrs.RuleGroupOverrides[0].Exclusions, 2)
	require.Equal(t, *sMrs.RuleGroupOverrides[0].Exclusions[0].Selector, "Al")
	require.Equal(t, *sMrs.RuleGroupOverrides[0].Exclusions[1].Selector, "Knows")
}

func TestRuleGroupScopeDoesntApplyToRuleScope(t *testing.T) {
	mrs := getTestRuleSetOne()

	logrus.SetLevel(logrus.DebugLevel)

	dcri := &DeleteManagedRuleExclusionInput{
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleVariable: "RequestHeaderNames",
		ExclusionRuleSelector: "Toast",
		RuleGroup:             "JAVA",
		Scope:                 ScopeRuleGroup,
		Debug:                 true,
	}

	sMrs, err := stripFromManagedRuleSet(dcri, &mrs)
	require.NoError(t, err)
	require.NotEmpty(t, sMrs)
	require.Len(t, sMrs.RuleGroupOverrides, 1)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules, 2)
	require.Len(t, sMrs.RuleGroupOverrides[0].Rules[0].Exclusions, 1)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].MatchVariable)
	require.Equal(t, armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEndsWith, *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].SelectorMatchOperator)
	require.Equal(t, "Toast", *sMrs.RuleGroupOverrides[0].Rules[1].Exclusions[0].Selector)
	require.Len(t, sMrs.Exclusions, 3)
	require.Equal(t, "Relax", *sMrs.Exclusions[0].Selector)
	require.Equal(t, "Your", *sMrs.Exclusions[1].Selector)
	require.Equal(t, "Eyes", *sMrs.Exclusions[2].Selector)
	require.Len(t, sMrs.RuleGroupOverrides[0].Exclusions, 3)
	require.Equal(t, *sMrs.RuleGroupOverrides[0].Exclusions[0].Selector, "Al")
	require.Equal(t, *sMrs.RuleGroupOverrides[0].Exclusions[1].Selector, "Knows")
	require.Equal(t, *sMrs.RuleGroupOverrides[0].Exclusions[2].Selector, "all")
}
