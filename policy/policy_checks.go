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
	case p.Properties.ManagedRules == nil:
		logging.Debugf("%s | policy %s has no managed rules", valueOrDash(p.Name), funcName)
		return false, 0
	case len(p.Properties.ManagedRules.ManagedRuleSets) == 0:
		logging.Debugf("%s | policy %s has no managed rule sets", valueOrDash(p.Name), funcName)
		return false, 0
	default:
		return true, len(p.Properties.ManagedRules.ManagedRuleSets)
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

	for _, rsOne := range one.Properties.ManagedRules.ManagedRuleSets {
		for _, rsTwo := range two.Properties.ManagedRules.ManagedRuleSets {
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
	case p.Properties.CustomRules == nil:
		logging.Debugf("%s | policy %s has no custom rules", valueOrDash(p.Name), funcName)
		return false, 0
	case len(p.Properties.CustomRules.Rules) == 0:
		logging.Debugf("%s | policy %s has no custom rules", valueOrDash(p.Name), funcName)
		return false, 0
	default:
		return true, len(p.Properties.CustomRules.Rules)
	}
}
