package policy

// ExclusionScope identifies which level of a managed rule set an exclusion is
// attached to. Azure applies its per-scope limits to each level independently,
// and add and delete both route on it, so it was worth taking out of a bare
// string: the three constants below are the only meaningful values.
type ExclusionScope string

const (
	ScopeRuleSet   ExclusionScope = "ruleSet"
	ScopeRuleGroup ExclusionScope = "ruleGroup"
	ScopeRule      ExclusionScope = "rule"
)

// Title renders the scope for display, e.g. "Rule Group". An unrecognised
// scope renders empty, as the string switch it replaced did.
func (s ExclusionScope) Title() string {
	switch s {
	case ScopeRule:
		return "Rule"
	case ScopeRuleGroup:
		return "Rule Group"
	case ScopeRuleSet:
		return "Rule Set"
	default:
		return ""
	}
}

// Lower renders the scope lowercase, e.g. "rule group", which is how the
// exclusion limit messages and the add-exclusion summary name it.
func (s ExclusionScope) Lower() string {
	switch s {
	case ScopeRule:
		return "rule"
	case ScopeRuleGroup:
		return "rule group"
	case ScopeRuleSet:
		return "rule set"
	default:
		return ""
	}
}
