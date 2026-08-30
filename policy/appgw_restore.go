package policy

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"
	"github.com/jonhadfield/azwaf/session"
)

// ProcessAppGWPolicyChangesInput is the AppGW analogue of ProcessPolicyChangesInput.
type ProcessAppGWPolicyChangesInput struct {
	Session          *session.Session
	PolicyName       string
	SubscriptionID   string
	ResourceGroup    string
	PolicyPostChange armnetwork.WebApplicationFirewallPolicy
	ShowDiff         bool
	DryRun           bool
	Backup           bool
	Debug            bool
}

// ProcessAppGWPolicyChanges fetches the existing AppGW policy, optionally
// shows a diff and creates a pre-change backup, then pushes the new policy.
func ProcessAppGWPolicyChanges(input *ProcessAppGWPolicyChangesInput) error {
	funcName := helpers.GetFunctionName()

	preChange, err := GetRawAppGWPolicy(input.Session, input.SubscriptionID, input.ResourceGroup, input.PolicyName)
	if err != nil {
		// the existing policy may not exist yet (first-time restore). only treat
		// "not found" as non-fatal; everything else is a real error.
		if !isAppGWNotFound(err) {
			return fmt.Errorf("%s - %w", funcName, err)
		}

		preChange = nil
	}

	if input.ShowDiff && preChange != nil {
		if err := DisplayPolicyDiff(preChange, input.PolicyPostChange); err != nil {
			return fmt.Errorf("%s - %w", funcName, err)
		}
	}

	if input.DryRun {
		logging.Infof("%s | changes were not applied as dry-run was requested", funcName)

		return nil
	}

	if input.Backup && preChange != nil {
		policyID := ""
		if preChange.ID != nil {
			policyID = *preChange.ID
		}

		err := BackupAppGWPolicy(&WrappedAppGWPolicy{
			SubscriptionID: input.SubscriptionID,
			ResourceGroup:  input.ResourceGroup,
			Name:           input.PolicyName,
			Policy:         *preChange,
			PolicyID:       policyID,
			AppVersion:     input.Session.AppVersion,
			WAFType:        WAFTypeAppGW,
		}, BackupDestination{
			FailFast: true,
			Path:     input.Session.BackupsDir,
		})
		if err != nil {
			return err
		}
	}

	return PushAppGWPolicy(input.Session, &PushAppGWPolicyInput{
		Name:          input.PolicyName,
		Subscription:  input.SubscriptionID,
		ResourceGroup: input.ResourceGroup,
		Policy:        input.PolicyPostChange,
		Debug:         input.Debug,
	})
}

func isAppGWNotFound(err error) bool {
	if err == nil {
		return false
	}

	// prefer the typed check: a 403/409 etc. containing "NotFound" in its
	// message must not be mistaken for a missing policy
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == http.StatusNotFound
	}

	msg := err.Error()

	return strings.Contains(msg, "ResourceNotFound") ||
		strings.Contains(msg, "NotFound") ||
		strings.Contains(msg, "404")
}

type appgwRestorePair struct {
	original, updated *WrappedAppGWPolicy
}

func loadExistingAppGWPolicy(s *session.Session, targetPolicy string) (*WrappedAppGWPolicy, error) {
	if targetPolicy == "" {
		return nil, nil
	}

	rid := config.ParseResourceID(targetPolicy)
	if rid.Name == "" {
		return nil, fmt.Errorf("invalid AppGW WAF policy id: %s", targetPolicy)
	}

	p, err := GetRawAppGWPolicy(s, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
	if err != nil {
		if isAppGWNotFound(err) {
			return nil, nil
		}

		return nil, err
	}

	return &WrappedAppGWPolicy{
		Date:           time.Now().UTC(),
		SubscriptionID: rid.SubscriptionID,
		ResourceGroup:  rid.ResourceGroup,
		Name:           rid.Name,
		Policy:         *p,
		PolicyID:       rid.Raw,
		WAFType:        WAFTypeAppGW,
	}, nil
}

// CompileAppGWPoliciesToRestore mirrors CompilePoliciesToRestore for AppGW.
func CompileAppGWPoliciesToRestore(s *session.Session, backups []WrappedAppGWPolicy, i *RestorePoliciesInput) ([]appgwRestorePair, error) {
	funcName := helpers.GetFunctionName()

	var results []appgwRestorePair

	for _, backup := range backups {
		matchID := backup.PolicyID
		if i.TargetPolicy != "" {
			matchID = i.TargetPolicy
		}

		var existing *WrappedAppGWPolicy

		if matchID != "" {
			var err error
			existing, err = loadExistingAppGWPolicy(s, matchID)
			if err != nil {
				return nil, fmt.Errorf("%s - %w", funcName, err)
			}
		}

		var patch GeneratePolicyPatchOutput
		if existing != nil {
			var err error
			patch, err = GenerateAppGWPolicyPatch(existing.Policy, backup.Policy)
			if err != nil {
				return nil, fmt.Errorf("%s - %w", funcName, err)
			}
		}

		matched := WrappedAppGWPolicy{}
		if existing != nil {
			matched = *existing
		}

		ok, err := shouldRestore(existing != nil, matched.asWrappedPolicy(), backup.asWrappedPolicy(), i, patch)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		restored := BuildRestoredAppGWPolicy(existing, &backup, i)
		var originalCopy *WrappedAppGWPolicy
		if existing != nil {
			c := *existing
			originalCopy = &c
		}

		results = append(results, appgwRestorePair{original: originalCopy, updated: &restored})
	}

	return results, nil
}

// asWrappedPolicy copies the identifying fields the two wrapper types share
// into a Front Door shaped WrappedPolicy, so shouldRestore can be reused for
// Application Gateway policies. It carries no policy body: shouldRestore reads
// only PolicyID and Date from either argument.
func (w WrappedAppGWPolicy) asWrappedPolicy() WrappedPolicy {
	return WrappedPolicy{
		Date:           w.Date,
		SubscriptionID: w.SubscriptionID,
		ResourceGroup:  w.ResourceGroup,
		Name:           w.Name,
		PolicyID:       w.PolicyID,
	}
}

// BuildRestoredAppGWPolicy is the AppGW analogue of BuildRestoredPolicy. It
// honours CustomRulesOnly / ManagedRulesOnly partial restore semantics.
func BuildRestoredAppGWPolicy(existing, backup *WrappedAppGWPolicy, i *RestorePoliciesInput) WrappedAppGWPolicy {
	// no existing policy: brand new restore
	if existing == nil || existing.PolicyID == "" {
		return WrappedAppGWPolicy{
			SubscriptionID: i.SubscriptionID,
			ResourceGroup:  i.ResourceGroup,
			Name:           backup.Name,
			Policy:         backup.Policy,
			WAFType:        WAFTypeAppGW,
		}
	}

	// copy the wrapper and clone Properties so the rule-set assignments below
	// don't write through the pointer shared with the caller's value. Deeper
	// fields remain shared, but they are only ever replaced wholesale here,
	// never mutated in place.
	updated := *existing
	if existing.Policy.Properties != nil {
		propsCopy := *existing.Policy.Properties
		updated.Policy.Properties = &propsCopy
	} else {
		updated.Policy.Properties = &armnetwork.WebApplicationFirewallPolicyPropertiesFormat{}
	}

	switch {
	case i.CustomRulesOnly:
		if backup.Policy.Properties != nil {
			updated.Policy.Properties.CustomRules = backup.Policy.Properties.CustomRules
		} else {
			updated.Policy.Properties.CustomRules = nil
		}
	case i.ManagedRulesOnly:
		if backup.Policy.Properties != nil {
			updated.Policy.Properties.ManagedRules = backup.Policy.Properties.ManagedRules
		} else {
			updated.Policy.Properties.ManagedRules = nil
		}
	default:
		// full replace of both rule sets
		if backup.Policy.Properties != nil {
			updated.Policy.Properties.CustomRules = backup.Policy.Properties.CustomRules
			updated.Policy.Properties.ManagedRules = backup.Policy.Properties.ManagedRules
		}
	}

	rid := config.ParseResourceID(updated.PolicyID)

	return WrappedAppGWPolicy{
		SubscriptionID: rid.SubscriptionID,
		ResourceGroup:  rid.ResourceGroup,
		Name:           rid.Name,
		Policy:         updated.Policy,
		PolicyID:       updated.PolicyID,
		WAFType:        WAFTypeAppGW,
	}
}

// restoreAppGWBackups walks compiled AppGW restore pairs and applies each.
func restoreAppGWBackups(s *session.Session, i *RestorePoliciesInput, backups []WrappedAppGWPolicy) error {
	funcName := helpers.GetFunctionName()

	if i.TargetPolicy != "" {
		// ensure only one backup file when targeting a single policy. The
		// caller (RestorePolicies) has already enforced this across both WAF
		// types, so this is a defensive check.
		if len(backups) > 1 {
			return fmt.Errorf("%s - restoring more than one backup to a single policy doesn't make sense", funcName)
		}

		if IsRIDHash(i.TargetPolicy) {
			return fmt.Errorf("%s - AppGW WAF restore targets must be a full resource id, not a hash", funcName)
		}
	}

	pairs, err := CompileAppGWPoliciesToRestore(s, backups, i)
	if err != nil {
		return err
	}

	if len(pairs) == 0 {
		return nil
	}

	// only retarget when the user explicitly supplied --target: without one,
	// each compiled pair already carries its own backup's identity, and
	// overriding pairs[0] could retarget the wrong backup if an earlier one
	// was skipped at the confirmation prompt
	if i.TargetPolicy != "" {
		rids, err := ConvertToResourceIDs([]string{i.TargetPolicy}, i.SubscriptionID)
		if err != nil {
			return err
		}

		pairs[0].updated.SubscriptionID = rids[0].SubscriptionID
		pairs[0].updated.ResourceGroup = rids[0].ResourceGroup
		pairs[0].updated.Name = rids[0].Name
	}

	for x := range pairs {
		if err := ProcessAppGWPolicyChanges(&ProcessAppGWPolicyChangesInput{
			Session:          s,
			PolicyName:       pairs[x].updated.Name,
			SubscriptionID:   pairs[x].updated.SubscriptionID,
			ResourceGroup:    pairs[x].updated.ResourceGroup,
			ShowDiff:         i.ShowDiff,
			PolicyPostChange: pairs[x].updated.Policy,
			DryRun:           i.DryRun,
			Backup:           i.AutoBackup,
			Debug:            i.Debug,
		}); err != nil {
			return err
		}
	}

	return nil
}
