package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/jonhadfield/azwaf/config"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
)

type RestorePoliciesInput struct {
	BaseCLIInput
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

// TODO: rGroup would be to override the resource group (in the filename) to restore to
// func restorePolicy(SubID, rGroup, name string, failFast, quiet bool, path string) (err error) {
//	t := time.Now().UTC().Format("20060102150405")
//	var p frontdoor.WebApplicationFirewallPolicy
//
//	var cwd string
//
//	if !quiet {
//		cwd, err = os.Getwd()
//		if err != nil {
//			return
//		}
//		msg := fmt.Sprintf("backing up Policy: %s", name)
//		statusOutput := PadToWidth(msg, " ", 0, true)
//		width, _, _ := terminal.GetSize(0)
//		if len(statusOutput) == width {
//			fmt.Printf(statusOutput[0:width-3] + "   \r")
//		} else {
//			fmt.Print(statusOutput)
//		}
//
//	}
//	p, err = getRawPolicy(SubID, rGroup, name)
//	if err != nil {
//		if failFast {
//			return err
//		}
//		log.Println(err)
//	}
//
//	var pj []byte
//	pj, err = json.MarshalIndent(p, "", "    ")
//	if err != nil {
//		if failFast {
//			return err
//		}
//		log.Println(err)
//	}
//	fName := fmt.Sprintf("%s+%s+%s+%s.json", SubID, rGroup, name, t)
//	var f *os.File
//	fp := filepath.Join(path, fName)
//	f, err = os.Create(fp)
//	if err != nil {
//		return
//	}
//	_, err = f.Write(pj)
//	if err != nil {
//		f.Close()
//		return
//	}
//
//	_ = f.Close()
//
//	if !quiet {
//		op := filepath.Clean(fp)
//		if strings.HasPrefix(op, cwd) {
//			op, err = filepath.Rel(cwd, op)
//			if err != nil {
//				return
//			}
//			op = "./" + op
//		}
//		log.Printf("restore written to: %s", op)
//	}
//	return
//
// }

func (i *RestorePoliciesInput) Validate() error {
	funcName := GetFunctionName()

	// check target policy if specified
	if i.TargetPolicy != "" {
		if ValidateResourceID(i.TargetPolicy, false) != nil {
			return fmt.Errorf(fmt.Sprintf("target policy '%s' is invalid", i.TargetPolicy), funcName)
		}
	}

	return nil
}

// RestorePolicies loads existing backup(s) from files and then adds/overwrites based on user's choices
func RestorePolicies(i *RestorePoliciesInput) (err error) {
	funcName := GetFunctionName()

	if err = i.Validate(); err != nil {
		return err
	}

	s := session.New()
	s.AppVersion = i.AppVersion

	if oerr := i.Validate(); oerr != nil {
		return oerr
	}

	// load policies from path
	logrus.Debugf("%s | loading paths %s", strings.Join(i.BackupsPaths, ", "), funcName)

	wps, oerr := LoadBackupsFromPaths(i.BackupsPaths)
	if oerr != nil {
		return oerr
	}

	if len(wps) == 0 {
		return fmt.Errorf(fmt.Sprintf("no backup files could be found in paths: %s", strings.Join(i.BackupsPaths, ", ")), funcName)
	}

	if i.TargetPolicy != "" {
		// ensure only single backup file loaded if targeting a policy
		if len(wps) > 1 {
			return fmt.Errorf("%s - restoring more than one backup to a single policy doesn't make sense", funcName)
		}

		if IsRIDHash(i.TargetPolicy) {
			i.TargetPolicy, err = GetPolicyRIDByHash(nil, i.SubscriptionID, i.TargetPolicy)
			if err != nil {
				return err
			}
		}
	} else {
		// if no target policy specified, then retrieve from backup
		i.TargetPolicy = wps[0].PolicyID
		logrus.Debugf("retrieved target id from backup: %s", i.TargetPolicy)
	}

	// restore loaded backups
	policies, err := CompilePoliciesToRestore(s, wps, i)
	if err != nil {
		return
	}

	if len(policies) > 0 {
		// if target policy specified, there can be only one
		if i.TargetPolicy != "" {
			var rIDs []config.ResourceID

			rIDs, err = ConvertToResourceIDs([]string{i.TargetPolicy}, i.SubscriptionID)
			if err != nil {
				return
			}

			policies[0].updated.SubscriptionID = rIDs[0].SubscriptionID
			policies[0].updated.ResourceGroup = rIDs[0].ResourceGroup
			policies[0].updated.Name = rIDs[0].Name
		}

		for x := range policies {
			err = ProcessPolicyChanges(&ProcessPolicyChangesInput{
				Session:          s,
				PolicyName:       policies[x].updated.Name,
				SubscriptionID:   policies[x].updated.SubscriptionID,
				ResourceGroup:    policies[x].updated.ResourceGroup,
				ShowDiff:         i.ShowDiff,
				PolicyPostChange: policies[x].updated.Policy,
				DryRun:           i.DryRun,
				Backup:           i.AutoBackup,
				Debug:            i.Debug,
			})
			if err != nil {
				return
			}
		}
	}

	return
}

type restorePair struct {
	original, updated *WrappedPolicy
}

func loadExistingPolicies(s *session.Session, targetPolicy, subscriptionID string) ([]WrappedPolicy, error) {
	var filterIDs []string
	if targetPolicy != "" {
		filterIDs = []string{targetPolicy}
	}

	logrus.Debugf("retrieving target policy: %s", targetPolicy)

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
			logrus.Warn("target policy's custom rules are identical to those in backup")
			return false, nil
		}

		if i.ManagedRulesOnly && patch.ManagedRuleChanges == 0 {
			logrus.Warn("target policy's Managed rules are identical to those in backup")
			return false, nil
		}

		if patch.TotalRuleDifferences == 0 {
			logrus.Warn("target policy rules are identical to backup")
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
	case i.TargetPolicy != "" && i.DryRun:
		logrus.Debug("dry run only")
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
		logrus.Debugf("%s | found existing policy matching id %s", funcName, matchID)

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

		restored := BuildRestoredPolicy(&matched, &backup, i)
		results = append(results, restorePair{original: &matched, updated: &restored})
	}

	return results, nil
}

// BuildRestoredPolicy accepts two policies (existing and backup) and options on which parts (Custom and or Managed rules) to replace
// without options, the Original will have both Custom and Managed rules parts replaced
// options allow for Custom or Managed rules in Original to replaced with those in backup
func BuildRestoredPolicy(existing, backup *WrappedPolicy, i *RestorePoliciesInput) WrappedPolicy {
	funcName := GetFunctionName()
	// take a backup of the existing that we'll apply the updates to
	// otherwise we're updating the original that we want to later use in a comparison
	copyOfOriginalPolicy, err := CopyWrappedPolicy(existing)
	if err != nil {
		logrus.Fatalf("%s | failed to copy policy", funcName)
	}

	// if there isn't an existing Policy, then just add backup
	if copyOfOriginalPolicy.PolicyID == "" {
		return WrappedPolicy{
			SubscriptionID: i.SubscriptionID,
			ResourceGroup:  i.ResourceGroup,
			Name:           backup.Name,
			Policy:         backup.Policy,
		}
	}

	switch {
	case i.CustomRulesOnly:
		copyOfOriginalPolicy.Policy.Properties.CustomRules.Rules = backup.Policy.Properties.CustomRules.Rules
		rID := config.ParseResourceID(copyOfOriginalPolicy.PolicyID)

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         copyOfOriginalPolicy.Policy,
			PolicyID:       copyOfOriginalPolicy.PolicyID,
		}
	case i.ManagedRulesOnly:
		if backup.Policy.Properties.ManagedRules == nil {
			copyOfOriginalPolicy.Policy.Properties.ManagedRules = nil
		} else {
			copyOfOriginalPolicy.Policy.Properties.ManagedRules = backup.Policy.Properties.ManagedRules
		}

		rID := config.ParseResourceID(copyOfOriginalPolicy.PolicyID)

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         copyOfOriginalPolicy.Policy,
			PolicyID:       copyOfOriginalPolicy.PolicyID,
		}
	default:
		// if both Original and backup are provided, then return Original with both Custom and Managed rules replaced
		rID := config.ParseResourceID(copyOfOriginalPolicy.PolicyID)

		copyOfOriginalPolicy.Policy.Properties.CustomRules = backup.Policy.Properties.CustomRules

		copyOfOriginalPolicy.Policy.Properties.ManagedRules = backup.Policy.Properties.ManagedRules

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         copyOfOriginalPolicy.Policy,
			PolicyID:       copyOfOriginalPolicy.PolicyID,
		}
	}
}
