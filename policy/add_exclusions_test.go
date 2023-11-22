package policy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/wI2L/jsondiff"
)

func TestGetMatchingDefaultRuleDefinitionMissing(t *testing.T) {
	defs, err := LoadManagedRulesetDefinitions()
	require.NoError(t, err)

	matchingDefs := getMatchingDefaultDefinitions(&getMatchingDefaultDefinitionsInput{
		mrsdl:  defs,
		ruleID: "944259",
		// groupName:      "",
		ruleSetType:    "Microsoft_DefaultRuleSet",
		ruleSetVersion: "1.1",
	})

	require.Nil(t, matchingDefs.RuleSetDefinition)
	require.Nil(t, matchingDefs.RuleGroupDefinition)
	require.Nil(t, matchingDefs.RuleDefinition)
}

func TestGetMatchingDefaultRuleDefinition(t *testing.T) {
	defs, err := LoadManagedRulesetDefinitions()
	require.NoError(t, err)

	matchingDefs := getMatchingDefaultDefinitions(&getMatchingDefaultDefinitionsInput{
		mrsdl:  defs,
		ruleID: "944250",
		// groupName:      "",
		ruleSetType:    "Microsoft_DefaultRuleSet",
		ruleSetVersion: "1.1",
	})

	require.NotNil(t, matchingDefs.RuleSetDefinition)
	require.NotNil(t, matchingDefs.RuleGroupDefinition)
	require.NotNil(t, matchingDefs.RuleDefinition)
}

// func TestAddRuleExclusionRuleWithoutExistingExclusions(t *testing.T) {
// 	mrs := getTestRuleSetOne()
//
// 	ruleSetDefinitions, err := LoadManagedRulesetDefinitions()
// 	require.NoError(t, err)
//
// 	logrus.SetLevel(logrus.DebugLevel)
//
// 	dcri := AddManagedRuleExclusionInput{
// 		DryRun:                false,
// 		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
// 		RuleSetType:           mrs.RuleSetType,
// 		RuleSetVersion:        mrs.RuleSetVersion,
// 		RuleSetDefinitions:    ruleSetDefinitions,
// 		RuleID:                "944250",
// 		ExclusionRuleVariable: armfrontdoor.ManagedRuleExclusionMatchVariable("RequestBodyPostArgNames"),
// 		ExclusionRuleOperator: armfrontdoor.ManagedRuleExclusionSelectorMatchOperator("EndsWith"),
// 		ExclusionRuleSelector: "Giraffe",
// 		Debug:                 true,
// 		Scope:                 ScopeRule,
// 	}
//
// 	err = addManagedRuleExclusion(&dcri)
// 	require.NoError(t, err)
// 	err = addManagedRuleExclusion(&dcri)
// 	fmt.Println(err)
// 	require.ErrorContains(t, err, errors.Errors[errors.ExclusionAlreadyExists])
// }

// func TestAddRuleExclusionInvalidOperator(t *testing.T) {
// 	mrs := getTestRuleSetOne()
//
// 	logrus.SetLevel(logrus.DebugLevel)
//
// 	dcri := AddManagedRuleExclusionInput{
// 		DryRun:                false,
// 		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
// 		RuleID:                "265220",
// 		ExclusionRuleVariable: "RequestBodyPostArgNames",
// 		ExclusionRuleOperator: "Has",
// 		ExclusionRuleSelector: "Elephant",
// 		Debug:                 true,
// 		Scope:                 ScopeRule,
// 	}
//
// 	err := addManagedRuleExclusion(&dcri)
// 	require.Error(t, err)
// 	require.ErrorContains(t, err, "invalid match operator")
// }
//
// func TestAddRuleExclusionInvalidVariable(t *testing.T) {
// 	mrs := getTestRuleSetOne()
//
// 	logrus.SetLevel(logrus.DebugLevel)
//
// 	dcri := AddManagedRuleExclusionInput{
// 		DryRun:                false,
// 		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
// 		RuleID:                "265220",
// 		ExclusionRuleVariable: "RequestMethod",
// 		ExclusionRuleOperator: "StartsWith",
// 		ExclusionRuleSelector: "Elephant",
// 		Debug:                 true,
// 		Scope:                 ScopeRule,
// 	}
//
// 	err := addManagedRuleExclusion(&dcri)
// 	require.Error(t, err)
// 	require.ErrorContains(t, err, "invalid match variable")
// }

func TestAddRuleExclusionRuleNotFound(t *testing.T) {
	mrs := getTestRuleSetOne()

	logrus.SetLevel(logrus.DebugLevel)

	ruleSetDefinitions, err := LoadManagedRulesetDefinitions()
	require.NoError(t, err)

	err = addManagedRuleExclusion(&AddManagedRuleExclusionInput{
		DryRun:                false,
		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
		RuleSetDefinitions:    ruleSetDefinitions,
		RuleID:                "0000123",
		ExclusionRuleVariable: "RequestBodyPostArgNames",
		ExclusionRuleOperator: "StartsWith",
		ExclusionRuleSelector: "Elephant",
		Debug:                 true,
		Scope:                 ScopeRule,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "not found")
}

// TODO: ParseConfig
// func TestAddRuleExclusion(t *testing.T) {
// 	mrs := getTestRuleSetOne()
//
// 	logrus.SetLevel(logrus.DebugLevel)
//
// 	dcri := AddManagedRuleExclusionInput{
// 		DryRun:                false,
// 		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
// 		RuleID:                "265220",
// 		ExclusionRuleVariable: "RequestBodyPostArgNames",
// 		ExclusionRuleOperator: "StartsWith",
// 		ExclusionRuleSelector: "Elephant",
// 		Debug:                 true,
// 		Scope:                 ScopeRule,
// 	}
//
// 	err := addManagedRuleExclusion(&dcri)
// 	require.NoError(t, err)
// 	err = addManagedRuleExclusion(&dcri)
// 	require.ErrorContains(t, err, errors.Errors[errors.ExclusionAlreadyExists])
// }

//
// func TestAddManagedRuleExclusionCLIInput(t testing.T) {
// 	input := AddManagedRuleExclusionCLIInput{
// 		BaseCLIInput:          BaseCLIInput{},
// 		SubscriptionID:        "",
// 		PolicyID:              "",
// 		RawRID:                   ResourceID{},
// 		RuleSet:               "",
// 		RuleGroup:             "",
// 		RuleID:                "",
// 		exclusionRuleVariable: "",
// 		exclusionRuleOperator: "",
// 		exclusionRuleSelector: "",
// 		Debug:                 false,
// 	}
//
// 	input.ParseConfig()
// }

// func TestAddRuleExclusionMixedOperatorCase(t *testing.T) {
// 	mrs := getTestRuleSetOne()
//
// 	logrus.SetLevel(logrus.DebugLevel)
//
// 	dcri := AddManagedRuleExclusionInput{
// 		DryRun:                false,
// 		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
// 		RuleID:                "265220",
// 		ExclusionRuleVariable: "RequestBodyPostArgNames",
// 		ExclusionRuleOperator: "startswith",
// 		ExclusionRuleSelector: "Elephant",
// 		Debug:                 true,
// 		Scope:                 ScopeRule,
// 	}
//
// 	err := addManagedRuleExclusion(&dcri)
// 	require.NoError(t, err)
// }
//
// func TestAddRuleExclusionMixedVariableCase(t *testing.T) {
// 	mrs := getTestRuleSetOne()
//
// 	logrus.SetLevel(logrus.DebugLevel)
//
// 	dcri := AddManagedRuleExclusionInput{
// 		DryRun:                false,
// 		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
// 		RuleID:                "265220",
// 		ExclusionRuleVariable: "requestBodypostArgNames",
// 		ExclusionRuleOperator: "StartsWith",
// 		ExclusionRuleSelector: "Elephant",
// 		Debug:                 true,
// 		Scope:                 ScopeRule,
// 	}
//
// 	err := addManagedRuleExclusion(&dcri)
// 	require.NoError(t, err)
// }

func TestAddRuleGroupExclusion(t *testing.T) {
	mrs := getTestRuleSetOne()

	orig, err := json.Marshal(mrs)
	require.NoError(t, err)

	logrus.SetLevel(logrus.DebugLevel)

	err = addManagedRuleExclusion(&AddManagedRuleExclusionInput{
		DryRun:                false,
		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
		RuleGroup:             "JAVA",
		ExclusionRuleVariable: "RequestBodyPostArgNames",
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleSelector: "Potato",
		Debug:                 true,
		Scope:                 ScopeRuleGroup,
	})
	require.NoError(t, err)

	err = addManagedRuleExclusion(&AddManagedRuleExclusionInput{
		DryRun:                false,
		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
		RuleGroup:             "JAVA",
		ExclusionRuleVariable: "RequestBodyPostArgNames",
		ExclusionRuleOperator: "EndsWith",
		ExclusionRuleSelector: "Potato",
		Debug:                 true,
		Scope:                 ScopeRuleGroup,
	})
	require.NotNil(t, err)

	var updated []byte
	updated, err = json.Marshal(mrs)
	require.NoError(t, err)

	var patch jsondiff.Patch
	patch, err = jsondiff.CompareJSON(orig, updated)
	require.NoError(t, err)
	require.Len(t, patch, 1)
	require.Contains(t, patch.String(), "Potato")
	require.NotEmpty(t, patch)
}

func TestAddRuleSetExclusion(t *testing.T) {
	mrs := getTestRuleSetOne()
	orig, err := json.Marshal(mrs)

	require.NoError(t, err)

	logrus.SetLevel(logrus.DebugLevel)

	dcri := &AddManagedRuleExclusionInput{
		DryRun:                false,
		RuleSets:              []*armfrontdoor.ManagedRuleSet{&mrs},
		RuleSetType:           StrToPointer("Microsoft_DefaultRuleSet"),
		RuleSetVersion:        StrToPointer("1.1"),
		ExclusionRuleVariable: "RequestCookieNames",
		ExclusionRuleOperator: "Contains",
		ExclusionRuleSelector: "Potato",
		Debug:                 true,
		Scope:                 ScopeRuleSet,
	}

	require.Nil(t, addManagedRuleExclusion(dcri))

	err = addManagedRuleExclusion(dcri)
	require.Error(t, err)
	require.ErrorContains(t, err, errExclusionAlreadyExists)

	var updated []byte
	updated, err = json.Marshal(mrs)
	require.NoError(t, err)

	var patch jsondiff.Patch
	patch, err = jsondiff.CompareJSON(orig, updated)
	require.NoError(t, err)

	fmt.Printf("patch: %+v\n", patch)
}
