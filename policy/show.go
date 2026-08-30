package policy

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"

	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/session"
)

type ShowPolicyInput struct {
	ConfigPath, SubscriptionID, PolicyID  string
	Full, Custom, Managed, Stats, Shadows bool
}

func ShowPolicy(in ShowPolicyInput) error {
	funcName := helpers.GetFunctionName()

	s, err := session.New()
	if err != nil {
		return err
	}

	policyID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: in.SubscriptionID,
		RawPolicyID:    in.PolicyID,
		ConfigPath:     in.ConfigPath,
	})
	if err != nil {
		return err
	}

	getPolicyInput := GetPolicyInput{
		Session:  s,
		PolicyID: policyID,
	}

	getPolicyOutput, err := getPolicyInput.GetPolicy()
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	// get Managed ruleset definitions
	var rsds []*armfrontdoor.ManagedRuleSetDefinition

	rsds, err = getRuleSetDefinitions(s, policyID.SubscriptionID)
	if err != nil {
		return err
	}

	OutputPolicy(OutputPolicyInput{
		policy:      getPolicyOutput.Policy,
		rsds:        rsds,
		showFull:    in.Full,
		showCustom:  in.Custom,
		showManaged: in.Managed,
		showStats:   in.Stats,
		showShadows: in.Shadows,
	})

	return nil
}
