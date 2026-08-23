package policy

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/logging"
)

// TODO: reintroduce this function once all the rule types are covered
// func HasDefaultDeny(p *armfrontdoor.WebApplicationFirewallPolicy) (defaultDeny bool, err error) {
// 	if p.Properties == nil || p.Properties.CustomRules == nil || p.Properties.CustomRules.Rules == nil {
// 		return false, errors.New("no custom rules defined")
// 	}
//
// 	// if Policy has "if not... then deny" then they do
// 	// if Policy has "if ip 0.0.0.0/0 then deny" then true
// 	for _, cr := range p.Properties.CustomRules.Rules {
// 		if *cr.EnabledState != "CustomRuleEnabledStateEnabled" {
// 			if CustomRuleHasDefaultDeny(cr) {
// 				return true, err
// 			}
// 		}
// 	}
//
// 	return
// }

func HasRuleSets(p *armfrontdoor.WebApplicationFirewallPolicy) (ok bool, noRuleSets int) {
	funcName := GetFunctionName()

	switch {
	case p == nil:
		logging.Debugf("%s | policy undefined", funcName)
		return false, 0
	case p.Properties == nil:
		logging.Debugf("%s | policy %s has no properties", valueOrDash(p.Name), funcName)
		return false, 0
	case policyManagedRuleSetList(p) == nil:
		logging.Debugf("%s | policy %s has no managed rules", valueOrDash(p.Name), funcName)
		return false, 0
	case len(policyManagedRuleSets(p)) == 0:
		logging.Debugf("%s | policy %s has no managed rule sets", valueOrDash(p.Name), funcName)
		return false, 0
	default:
		return true, len(policyManagedRuleSets(p))
	}
}

func HaveEqualRuleSets(one, two *armfrontdoor.WebApplicationFirewallPolicy) bool {
	funcName := GetFunctionName()
	oneOK, oneNumRuleSets := HasRuleSets(one)
	twoOK, twoNumRuleSets := HasRuleSets(two)

	switch {
	case !oneOK:
		logging.Debugf("%s | first policy hasn't got any rulesets", funcName)
		return false
	case !twoOK:
		logging.Debugf("%s | second policy hasn't got any rulesets", funcName)
		return false
	case oneNumRuleSets != twoNumRuleSets:
		logging.Debugf("%s | policies don't have same number of rulesets", funcName)
	}

	var matches int

	for _, rsOne := range policyManagedRuleSets(one) {
		for _, rsTwo := range policyManagedRuleSets(two) {
			if *rsOne.RuleSetType == *rsTwo.RuleSetType && *rsOne.RuleSetVersion == *rsTwo.RuleSetVersion {
				matches++

				if matches == oneNumRuleSets {
					return true
				}
			}
		}
	}

	return false
}

func HasCustomRules(p *armfrontdoor.WebApplicationFirewallPolicy) (ok bool, noRuleSets int) {
	funcName := GetFunctionName()

	switch {
	case p == nil:
		logging.Debugf("%s | policy undefined", funcName)
		return false, 0
	case p.Properties == nil:
		logging.Debugf("%s | policy %s has no properties", valueOrDash(p.Name), funcName)
		return false, 0
	case policyCustomRuleList(p) == nil:
		logging.Debugf("%s | policy %s has no custom rules", valueOrDash(p.Name), funcName)
		return false, 0
	case len(policyCustomRules(p)) == 0:
		logging.Debugf("%s | policy %s has no custom rules", valueOrDash(p.Name), funcName)
		return false, 0
	default:
		return true, len(policyCustomRules(p))
	}
}
