package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/logging"

	"github.com/jonhadfield/azwaf/session"
)

type RestorePoliciesInput struct {
	BaseCLIInput
	// Session optionally provides a pre-configured session; when nil a new
	// one is created. Tests inject a fake-backed session here.
	Session          *session.Session
	BackupsPaths     []string
	CustomRulesOnly  bool
	ManagedRulesOnly bool
	TargetPolicy     string
	ResourceGroup    string
	RIDs             []config.ResourceID
	ShowDiff         bool
	Force            bool
	FailFast         bool
}

func (i *RestorePoliciesInput) Validate() error {
	funcName := GetFunctionName()

	// check target policy if specified
	if i.TargetPolicy != "" {
		if ValidateResourceID(i.TargetPolicy, false) != nil {
			return fmt.Errorf("%s - target policy '%s' is invalid", funcName, i.TargetPolicy)
		}
	}

	return nil
}

// RestorePolicies loads existing backup(s) from files and then adds/overwrites
// based on the user's choices. Both Front Door and Application Gateway WAF
// backup files can be present in the supplied paths; each backup is dispatched
// to the matching API based on its embedded WAFType field (or the resource
// type of an explicit --target).
func RestorePolicies(i *RestorePoliciesInput) error {
	funcName := GetFunctionName()

	if err := i.Validate(); err != nil {
		return err
	}

	s := i.Session
	if s == nil {
		var serr error

		s, serr = session.New()
		if serr != nil {
			return serr
		}
	}

	s.AppVersion = i.AppVersion

	logging.Debugf("%s | loading paths %s", strings.Join(i.BackupsPaths, ", "), funcName)

	loaded, err := LoadAllBackupsFromPaths(i.BackupsPaths)
	if err != nil {
		return err
	}

	total := len(loaded.FrontDoor) + len(loaded.AppGW)
	if total == 0 {
		return fmt.Errorf("%s - no backup files could be found in paths: %s", funcName, strings.Join(i.BackupsPaths, ", "))
	}

	if i.TargetPolicy != "" && total > 1 {
		return fmt.Errorf("%s - restoring more than one backup to a single policy doesn't make sense", funcName)
	}

	// if a target was specified, validate it matches the type of the loaded backup
	if i.TargetPolicy != "" {
		targetType := WAFTypeFromResourceID(i.TargetPolicy)

		if !IsRIDHash(i.TargetPolicy) {
			if targetType == WAFTypeAppGW && len(loaded.AppGW) == 0 {
				return fmt.Errorf("%s - target is an Application Gateway WAF policy but the loaded backup is for Front Door", funcName)
			}

			if targetType == WAFTypeFrontDoor && len(loaded.FrontDoor) == 0 {
				return fmt.Errorf("%s - target is a Front Door WAF policy but the loaded backup is for Application Gateway", funcName)
			}
		}
	}

	if len(loaded.FrontDoor) > 0 {
		// pass a copy: restoreFrontDoorBackups writes resolved hashes and
		// backup-derived targets into TargetPolicy, and those must not leak
		// into the AppGW branch below
		fdInput := *i
		if err := restoreFrontDoorBackups(s, &fdInput, loaded.FrontDoor); err != nil {
			return err
		}
	}

	if len(loaded.AppGW) > 0 {
		if err := restoreAppGWBackups(s, i, loaded.AppGW); err != nil {
			return err
		}
	}

	return nil
}

// restoreFrontDoorBackups encapsulates the original RestorePolicies behaviour
// for Front Door WAF backups; it has been extracted so the AppGW path can sit
// alongside it. It mutates i.TargetPolicy, so callers must pass a copy of the
// input if they use it afterwards.
func restoreFrontDoorBackups(s *session.Session, i *RestorePoliciesInput, wps []WrappedPolicy) error {
	funcName := GetFunctionName()

	explicitTarget := i.TargetPolicy != ""

	if i.TargetPolicy != "" {
		if IsRIDHash(i.TargetPolicy) {
			resolved, err := GetPolicyRIDByHash(nil, i.SubscriptionID, i.TargetPolicy)
			if err != nil {
				return err
			}

			i.TargetPolicy = resolved
		}
	} else {
		i.TargetPolicy = wps[0].PolicyID
		logging.Debugf("retrieved target id from backup: %s", i.TargetPolicy)
	}

	policies, err := CompilePoliciesToRestore(s, wps, i)
	if err != nil {
		return err
	}

	if len(policies) == 0 {
		return nil
	}

	// only retarget when the user explicitly supplied --target: when the
	// target was derived from the first backup, every compiled policy
	// already carries that identity, making this override redundant
	if explicitTarget {
		rIDs, err := ConvertToResourceIDs([]string{i.TargetPolicy}, i.SubscriptionID)
		if err != nil {
			return err
		}

		policies[0].updated.SubscriptionID = rIDs[0].SubscriptionID
		policies[0].updated.ResourceGroup = rIDs[0].ResourceGroup
		policies[0].updated.Name = rIDs[0].Name
	}

	for x := range policies {
		if err := ProcessPolicyChanges(&ProcessPolicyChangesInput{
			Session:          s,
			PolicyName:       policies[x].updated.Name,
			SubscriptionID:   policies[x].updated.SubscriptionID,
			ResourceGroup:    policies[x].updated.ResourceGroup,
			ShowDiff:         i.ShowDiff,
			PolicyPostChange: policies[x].updated.Policy,
			DryRun:           i.DryRun,
			Backup:           i.AutoBackup,
			Debug:            i.Debug,
		}); err != nil {
			return fmt.Errorf("%s - %w", funcName, err)
		}
	}

	return nil
}

type restorePair struct {
	original, updated *WrappedPolicy
}

func loadExistingPolicies(s *session.Session, targetPolicy, subscriptionID string) ([]WrappedPolicy, error) {
	var filterIDs []string
	if targetPolicy != "" {
		filterIDs = []string{targetPolicy}
	}

	logging.Debugf("retrieving target policy: %s", targetPolicy)

	o, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		FilterResourceIDs: filterIDs,
		SubscriptionID:    subscriptionID,
	})
	if err != nil {
		return nil, err
	}

	return o.Policies, nil
}

func shouldRestore(foundExisting bool, matched WrappedPolicy, backup WrappedPolicy, i *RestorePoliciesInput, patch GeneratePolicyPatchOutput) (bool, error) {
	funcName := GetFunctionName()

	if foundExisting {
		if i.CustomRulesOnly && patch.CustomRuleChanges == 0 {
			logging.Warn("target policy's custom rules are identical to those in backup")
			return false, nil
		}

		if i.ManagedRulesOnly && patch.ManagedRuleChanges == 0 {
			logging.Warn("target policy's Managed rules are identical to those in backup")
			return false, nil
		}

		if patch.TotalRuleDifferences == 0 {
			logging.Warn("target policy rules are identical to backup")
			return false, nil
		}
	}

	var op string
	if i.CustomRulesOnly {
		op = "Custom "
	}

	if i.ManagedRulesOnly {
		op = "Managed "
	}

	switch {
	// dry runs against an existing policy proceed without prompting. The
	// foundExisting alternative matters for AppGW restores, which never
	// derive a TargetPolicy from the backup; without it a no-target dry run
	// would block on the interactive confirmation below.
	case i.DryRun && (i.TargetPolicy != "" || foundExisting):
		logging.Debug("dry run only")
		return true, nil
	case i.TargetPolicy != "" && !foundExisting:
		return false, fmt.Errorf("%s - target policy does not exist", funcName)
	case i.TargetPolicy != "" && foundExisting && !i.Force:
		if !Confirm(fmt.Sprintf("confirm replacement of %srules in target policy %s", op, i.TargetPolicy), fmt.Sprintf("with backup %s\ntaken %v", backup.PolicyID, backup.Date.Format(time.RFC850))) {
			return false, nil
		}
	case i.TargetPolicy == "" && foundExisting && !i.Force:
		if !Confirm(fmt.Sprintf("found an existing policy: %s", matched.PolicyID), fmt.Sprintf("confirm replacement of %srules with backup taken %v", op, backup.Date.Format(time.RFC850))) {
			return false, nil
		}
	case matched.PolicyID == "" && i.ResourceGroup == "":
		return false, fmt.Errorf("%s - unable to create New Policy without specifying its resource group", funcName)
	}

	return true, nil
}

func CompilePoliciesToRestore(s *session.Session, policyBackups []WrappedPolicy, i *RestorePoliciesInput) ([]restorePair, error) {
	funcName := GetFunctionName()

	existingPolicies, err := loadExistingPolicies(s, i.TargetPolicy, i.SubscriptionID)
	if err != nil {
		return nil, err
	}

	// compare each backup Policy id (or target policy id if provided) with existing Policy ids
	var results []restorePair
	for _, backup := range policyBackups {
		matchID := backup.PolicyID
		if i.TargetPolicy != "" {
			matchID = i.TargetPolicy
		}

		found, matched := MatchExistingPolicyByID(matchID, existingPolicies)
		logging.Debugf("%s | found existing policy matching id %s", funcName, matchID)

		var patch GeneratePolicyPatchOutput
		if found {
			patch, err = GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: matched, New: backup.Policy})
			if err != nil {
				return nil, err
			}
		}

		ok, err := shouldRestore(found, matched, backup, i, patch)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		restored, err := BuildRestoredPolicy(&matched, &backup, i)
		if err != nil {
			return nil, err
		}

		results = append(results, restorePair{original: &matched, updated: &restored})
	}

	return results, nil
}

// ensurePolicyProperties returns p's properties, creating them if absent, so a
// restore onto a policy that carries none does not panic.
func ensurePolicyProperties(p *armfrontdoor.WebApplicationFirewallPolicy) *armfrontdoor.WebApplicationFirewallPolicyProperties {
	if p.Properties == nil {
		p.Properties = &armfrontdoor.WebApplicationFirewallPolicyProperties{}
	}

	return p.Properties
}

// backupCustomRules and backupManagedRules read a backup's rules without
// assuming it has properties. A backup legitimately holds none when the policy
// it captured had none, in which case the restore clears the target's.
func backupCustomRules(p *armfrontdoor.WebApplicationFirewallPolicy) *armfrontdoor.CustomRuleList {
	if p.Properties == nil {
		return nil
	}

	return policyCustomRuleList(p)
}

func backupManagedRules(p *armfrontdoor.WebApplicationFirewallPolicy) *armfrontdoor.ManagedRuleSetList {
	if p.Properties == nil {
		return nil
	}

	return policyManagedRuleSetList(p)
}

// BuildRestoredPolicy accepts two policies (existing and backup) and options on which parts (Custom and or Managed rules) to replace
// without options, the Original will have both Custom and Managed rules parts replaced
// options allow for Custom or Managed rules in Original to replaced with those in backup
func BuildRestoredPolicy(existing, backup *WrappedPolicy, i *RestorePoliciesInput) (WrappedPolicy, error) {
	funcName := GetFunctionName()
	// take a backup of the existing that we'll apply the updates to
	// otherwise we're updating the original that we want to later use in a comparison
	copyOfOriginalPolicy, err := CopyWrappedPolicy(existing)
	if err != nil {
		return WrappedPolicy{}, fmt.Errorf("%s | failed to copy policy: %w", funcName, err)
	}

	// if there isn't an existing Policy, then just add backup
	if copyOfOriginalPolicy.PolicyID == "" {
		return WrappedPolicy{
			SubscriptionID: i.SubscriptionID,
			ResourceGroup:  i.ResourceGroup,
			Name:           backup.Name,
			Policy:         backup.Policy,
		}, nil
	}

	switch {
	case i.CustomRulesOnly:
		props := ensurePolicyProperties(&copyOfOriginalPolicy.Policy)
		if props.CustomRules == nil {
			props.CustomRules = &armfrontdoor.CustomRuleList{}
		}

		if src := backupCustomRules(&backup.Policy); src != nil {
			props.CustomRules.Rules = src.Rules
		} else {
			props.CustomRules.Rules = nil
		}

		rID := config.ParseResourceID(copyOfOriginalPolicy.PolicyID)

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         copyOfOriginalPolicy.Policy,
			PolicyID:       copyOfOriginalPolicy.PolicyID,
		}, nil
	case i.ManagedRulesOnly:
		ensurePolicyProperties(&copyOfOriginalPolicy.Policy).ManagedRules = backupManagedRules(&backup.Policy)

		rID := config.ParseResourceID(copyOfOriginalPolicy.PolicyID)

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         copyOfOriginalPolicy.Policy,
			PolicyID:       copyOfOriginalPolicy.PolicyID,
		}, nil
	default:
		// if both Original and backup are provided, then return Original with both Custom and Managed rules replaced
		rID := config.ParseResourceID(copyOfOriginalPolicy.PolicyID)

		props := ensurePolicyProperties(&copyOfOriginalPolicy.Policy)
		props.CustomRules = backupCustomRules(&backup.Policy)
		props.ManagedRules = backupManagedRules(&backup.Policy)

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         copyOfOriginalPolicy.Policy,
			PolicyID:       copyOfOriginalPolicy.PolicyID,
		}, nil
	}
}
