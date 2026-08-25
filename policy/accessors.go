package policy

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
)

// Accessors for the Front Door policy structure.
//
// The SDK models a policy as optional pointers at every level —
// Policy → Properties → CustomRules → Rules — so reading a rule means checking
// three of them. Consumers either repeated those checks or, more often, skipped
// them and panicked on a policy the API had not fully populated.
//
// These accessors do the checking once. Ranging over the nil slice they return
// is a no-op, so callers can read straight through without guards.
//
// They deliberately do not normalise in place. Diffs are computed by marshalling
// both sides to JSON (GeneratePolicyPatch), where an absent container and an
// empty one are not equal, so substituting empties would invent differences,
// change what is pushed to Azure, and change what auto-backups contain.
//
// Two things they do not cover: nil *entries* within a returned slice, which
// callers still skip individually, and optional leaf fields such as Name or
// Priority, which derefOrEmpty and valueOrDash handle.

// policyCustomRules returns a policy's custom rules.
func policyCustomRules(p *armfrontdoor.WebApplicationFirewallPolicy) []*armfrontdoor.CustomRule {
	if p == nil || p.Properties == nil || p.Properties.CustomRules == nil {
		return nil
	}

	return p.Properties.CustomRules.Rules
}

// policyCustomRuleList returns the container holding a policy's custom rules,
// for the few callers that replace or count it wholesale.
func policyCustomRuleList(p *armfrontdoor.WebApplicationFirewallPolicy) *armfrontdoor.CustomRuleList {
	if p == nil || p.Properties == nil {
		return nil
	}

	return p.Properties.CustomRules
}

// policyManagedRuleSets returns a policy's managed rule sets.
func policyManagedRuleSets(p *armfrontdoor.WebApplicationFirewallPolicy) []*armfrontdoor.ManagedRuleSet {
	if p == nil || p.Properties == nil || p.Properties.ManagedRules == nil {
		return nil
	}

	return p.Properties.ManagedRules.ManagedRuleSets
}

// policyManagedRuleSetList returns the container holding a policy's managed
// rule sets, for callers that replace or compare it wholesale.
func policyManagedRuleSetList(p *armfrontdoor.WebApplicationFirewallPolicy) *armfrontdoor.ManagedRuleSetList {
	if p == nil || p.Properties == nil {
		return nil
	}

	return p.Properties.ManagedRules
}

// ruleSetGroupOverrides returns a rule set's rule group overrides.
func ruleSetGroupOverrides(rs *armfrontdoor.ManagedRuleSet) []*armfrontdoor.ManagedRuleGroupOverride {
	if rs == nil {
		return nil
	}

	return rs.RuleGroupOverrides
}

// ruleSetExclusions returns a rule set's own exclusions.
func ruleSetExclusions(rs *armfrontdoor.ManagedRuleSet) []*armfrontdoor.ManagedRuleExclusion {
	if rs == nil {
		return nil
	}

	return rs.Exclusions
}

// groupOverrideRules returns the rule overrides within a rule group override.
func groupOverrideRules(rgo *armfrontdoor.ManagedRuleGroupOverride) []*armfrontdoor.ManagedRuleOverride {
	if rgo == nil {
		return nil
	}

	return rgo.Rules
}

// groupOverrideExclusions returns a rule group override's exclusions.
func groupOverrideExclusions(rgo *armfrontdoor.ManagedRuleGroupOverride) []*armfrontdoor.ManagedRuleExclusion {
	if rgo == nil {
		return nil
	}

	return rgo.Exclusions
}

// ruleOverrideExclusions returns a rule override's exclusions.
func ruleOverrideExclusions(ro *armfrontdoor.ManagedRuleOverride) []*armfrontdoor.ManagedRuleExclusion {
	if ro == nil {
		return nil
	}

	return ro.Exclusions
}

// derefOrEmpty reads an optional string field without assuming the API set it.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

// ruleSetListSets returns the rule sets held in a list.
func ruleSetListSets(l *armfrontdoor.ManagedRuleSetList) []*armfrontdoor.ManagedRuleSet {
	if l == nil {
		return nil
	}

	return l.ManagedRuleSets
}

// exclusionScope names one place exclusions can be attached. Azure caps each
// at 100 independently, so they have to be counted separately: summing them and
// comparing the total against the per-scope limit both cries wolf (three scopes
// of 40 is not a breach) and misses real breaches.
type exclusionScope struct {
	// scope is "rule set", "rule group" or "rule".
	scope string
	// name identifies the individual rule set, group or rule.
	name  string
	count int
}

// policyExclusionScopes returns every scope in a policy that holds exclusions,
// with its count. One entry per rule set, per rule group override and per rule
// override — not aggregated, because the limit applies to each individually.
func policyExclusionScopes(p *armfrontdoor.WebApplicationFirewallPolicy) []exclusionScope {
	var scopes []exclusionScope

	for _, rs := range policyManagedRuleSets(p) {
		ruleSetName := ruleSetDisplayName(rs)

		if c := len(ruleSetExclusions(rs)); c > 0 {
			scopes = append(scopes, exclusionScope{scope: "rule set", name: ruleSetName, count: c})
		}

		for _, rgo := range ruleSetGroupOverrides(rs) {
			if c := len(groupOverrideExclusions(rgo)); c > 0 {
				scopes = append(scopes, exclusionScope{
					scope: "rule group",
					name:  ruleSetName + "/" + derefOrEmpty(rgo.RuleGroupName),
					count: c,
				})
			}

			for _, ro := range groupOverrideRules(rgo) {
				if c := len(ruleOverrideExclusions(ro)); c > 0 {
					scopes = append(scopes, exclusionScope{
						scope: "rule",
						name:  ruleSetName + "/" + derefOrEmpty(rgo.RuleGroupName) + "/" + derefOrEmpty(ro.RuleID),
						count: c,
					})
				}
			}
		}
	}

	return scopes
}

// ruleSetDisplayName renders a rule set as "<type>_<version>".
func ruleSetDisplayName(rs *armfrontdoor.ManagedRuleSet) string {
	if rs == nil {
		return ""
	}

	return derefOrEmpty(rs.RuleSetType) + "_" + derefOrEmpty(rs.RuleSetVersion)
}
