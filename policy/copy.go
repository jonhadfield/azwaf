package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
)

// CopyRulesInput are the arguments provided to the CopyRules function.
type CopyRulesInput struct {
	// BaseCLIInput carries SubscriptionID, DryRun, Debug, Quiet and AppVersion.
	// Those five were previously redeclared below, shadowing the embedded copies
	// that cmd/commands/cmdCopy.go actually populates, so reads of i.DryRun and
	// i.SubscriptionID always saw zero values and --dry-run pushed anyway.
	BaseCLIInput
	// Session optionally provides a pre-configured session; when nil a new
	// one is created. Tests inject a fake-backed session here.
	Session          *session.Session
	Source           string
	Target           string
	CustomRulesOnly  bool
	ManagedRulesOnly bool
	ShowDiff         bool
	Async            bool
}

// CopyRules copies managed and custom rules between policies with matching rule sets
func CopyRules(i CopyRulesInput) error {
	funcName := helpers.GetFunctionName()
	if strings.EqualFold(i.Source, i.Target) {
		return fmt.Errorf("%s - source and target must be different", funcName)
	}

	s := i.Session
	if s == nil {
		var serr error

		if s, serr = session.New(); serr != nil {
			return serr
		}
	}

	SourceResourceID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: i.SubscriptionID,
		RawPolicyID:    i.Source,
		ConfigPath:     i.ConfigPath,
	})
	if err != nil {
		return err
	}

	TargetResourceID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: i.SubscriptionID,
		RawPolicyID:    i.Target,
		ConfigPath:     i.ConfigPath,
	})
	if err != nil {
		return err
	}

	logging.Debug("copy source: ", i.Source)
	logging.Debug("copy target: ", i.Target)

	sourcePolicy, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    SourceResourceID.SubscriptionID,
		FilterResourceIDs: []string{SourceResourceID.Raw},
	})
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	if len(sourcePolicy.Policies) == 0 {
		return fmt.Errorf("%s - source policy not found", funcName)
	}

	targetPolicy, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    TargetResourceID.SubscriptionID,
		FilterResourceIDs: []string{TargetResourceID.Raw},
	})
	if err != nil {
		return err
	}

	if len(targetPolicy.Policies) == 0 {
		return fmt.Errorf("%s - target policy not found", funcName)
	}

	if !i.CustomRulesOnly && !HaveEqualRuleSets(&sourcePolicy.Policies[0].Policy, &targetPolicy.Policies[0].Policy) {
		return fmt.Errorf("%s - source and target policies must have matching managed rule set types and versions when copying managed rule settings", funcName)
	}

	logging.Debugf("%s | policies have matching managed ruleset types and versions", funcName)

	// check change is required
	o, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: sourcePolicy.Policies[0].Policy,
		New:      targetPolicy.Policies[0].Policy,
	})
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	logging.Debugf("%s | custom rule changes %d managed rule changes %d total differences %d", funcName, o.CustomRuleChanges, o.ManagedRuleChanges, o.TotalDifferences)

	switch {
	case o.CustomRuleChanges == 0 && i.CustomRulesOnly:
		logging.Warnf("%s | custom rules are already identical", funcName)

		return nil
	case o.ManagedRuleChanges == 0 && i.ManagedRulesOnly:
		logging.Warnf("%s | managed rules are already identical", funcName)

		return nil
	case o.TotalRuleDifferences == 0:
		logging.Warnf("%s | rules are already identical", funcName)

		return nil
	}

	updatedTarget, err := copyWrappedPolicyRules(&sourcePolicy.Policies[0], &targetPolicy.Policies[0], i.CustomRulesOnly, i.ManagedRulesOnly, i.AppVersion)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	return ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       updatedTarget.Name,
		SubscriptionID:   updatedTarget.SubscriptionID,
		ResourceGroup:    updatedTarget.ResourceGroup,
		PolicyPostChange: updatedTarget.Policy,
		ShowDiff:         i.ShowDiff,
		DryRun:           i.DryRun,
		Backup:           i.AutoBackup,
		Debug:            i.Debug,
		Async:            i.Async,
	})
}

// copyWrappedPolicyRules takes two policies and copies the chosen sections from source to the target
func copyWrappedPolicyRules(source, target *WrappedPolicy, customRulesOnly, managedRulesOnly bool, appVersion string) (*WrappedPolicy, error) {
	funcName := helpers.GetFunctionName()

	updatedTarget, err := copyPolicyRules(&source.Policy, &target.Policy, customRulesOnly, managedRulesOnly)
	if err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	if updatedTarget.ID == nil {
		return nil, fmt.Errorf("%s - updated policy has no id", funcName)
	}

	resourceID := config.ParseResourceID(*updatedTarget.ID)

	return &WrappedPolicy{
		Date:           time.Now(),
		SubscriptionID: resourceID.SubscriptionID,
		ResourceGroup:  resourceID.ResourceGroup,
		Name:           resourceID.Name,
		Policy:         *updatedTarget,
		PolicyID:       *updatedTarget.ID,
		AppVersion:     appVersion,
	}, nil
}

// copyPolicyRules takes two policies and copies the chosen sections from source to the target
func copyPolicyRules(source, target *armfrontdoor.WebApplicationFirewallPolicy, customRulesOnly, managedRulesOnly bool) (*armfrontdoor.WebApplicationFirewallPolicy, error) {
	funcName := helpers.GetFunctionName()

	if customRulesOnly && managedRulesOnly {
		return nil, fmt.Errorf("please choose only one of custom-only and managed-only, or neither to copy both")
	}

	// these were arms of the same switch as the managed-rules check below, so
	// the target arm could not be reached once an earlier one matched and a nil
	// target — or either policy with no Properties — panicked instead of erroring
	if source == nil || source.Properties == nil {
		return nil, fmt.Errorf("%s - source policy is missing", funcName)
	}

	if target == nil || target.Properties == nil {
		return nil, fmt.Errorf("%s - target policy is missing", funcName)
	}

	if (customRulesOnly || !managedRulesOnly) && policyManagedRuleSetList(source) == nil {
		return nil, fmt.Errorf("source policy has no managed rules")
	}

	switch {
	case customRulesOnly:
		logging.Debugf("%s | copying custom rules only", funcName)

		target.Properties.CustomRules = policyCustomRuleList(source)
	case managedRulesOnly:
		logging.Debugf("%s | copying managed rules only, from %#+v to %#+v",
			funcName, policyManagedRuleSetList(source), policyManagedRuleSetList(target))

		target.Properties.ManagedRules = policyManagedRuleSetList(source)
	default:
		logging.Debugf("%s | copying custom and managed rules onto %#+v", funcName, target.Properties)

		target.Properties.CustomRules = policyCustomRuleList(source)
		target.Properties.ManagedRules = policyManagedRuleSetList(source)
	}

	return target, nil
}

func (c *CopyRulesInput) Validate() error {
	funcName := helpers.GetFunctionName()

	if c.CustomRulesOnly && c.ManagedRulesOnly {
		return fmt.Errorf("%s - please choose only one of custom-only and managed-only, or neither to copy both", funcName)
	}

	if err := ValidateResourceID(c.Source, false); err != nil {
		return fmt.Errorf("%s - source id error: %w", funcName, err)
	}

	if err := ValidateResourceID(c.Target, false); err != nil {
		return fmt.Errorf("%s - target id error: %w", funcName, err)
	}

	if err := validateSubscriptionID(c.SubscriptionID); err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	return nil
}

// CopyPolicy takes an instance of a policy and returns a duplicate
func CopyPolicy(original armfrontdoor.WebApplicationFirewallPolicy) (armfrontdoor.WebApplicationFirewallPolicy, error) {
	funcName := helpers.GetFunctionName()

	originalBytes, err := json.Marshal(original)
	if err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	var duplicate armfrontdoor.WebApplicationFirewallPolicy
	if err = json.Unmarshal(originalBytes, &duplicate); err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	return duplicate, nil
}

// CopyWrappedPolicy takes an instance of a wrapped policy and returns a duplicate
func CopyWrappedPolicy(original *WrappedPolicy) (*WrappedPolicy, error) {
	funcName := helpers.GetFunctionName()

	var duplicate *WrappedPolicy

	originalBytes, err := json.Marshal(original)
	if err != nil {
		return duplicate, fmt.Errorf("%s - %w", funcName, err)
	}

	if err = json.Unmarshal(originalBytes, &duplicate); err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	return duplicate, nil
}
