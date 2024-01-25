//go:build integration

package it_test

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/policy"
	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	_ "github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
)

const integrationTestRulePrefix = "intTest"

var (
	testSinglePolicyId config.ResourceID
	testIdentifier     string
	subscriptionId     string
)

func TestMain(m *testing.M) {
	logrus.SetLevel(logrus.DebugLevel)

	subscriptionId = os.Getenv("AZWAF_TEST_SUBSCRIPTION_ID")

	tpi := os.Getenv("AZWAF_TEST_POLICY_ID")

	if tpi != "" {
		testSinglePolicyId = config.ParseResourceID(tpi)
		if testSinglePolicyId.Name == "" {
			logrus.Fatalf("failed to parse policy id: %s", tpi)
			os.Exit(1)
		}
	}

	testIdentifier = randString(10)

	exitVal := m.Run()

	os.Exit(exitVal)
}

func TestGetPolicy(t *testing.T) {
	if testSinglePolicyId.Name == "" {
		t.Skipf("AZWAF_TEST_POLICY_ID not set")
	}

	gpi := policy.GetPolicyInput{
		Session:  session.New(),
		PolicyID: testSinglePolicyId,
	}

	out, err := gpi.GetPolicy()
	require.NoError(t, err)
	require.NotNil(t, out.Policy)
	require.NotNil(t, out.Policy.ID)
	require.True(t, strings.EqualFold(testSinglePolicyId.Raw, *out.Policy.ID))
}

// func testDeleteSetup(s *session.Session, p *armfrontdoor.WebApplicationFirewallPolicy, customRules []*armfrontdoor.CustomRule) {
//
// }

// TestDeleteCustomRuleByPriority adds a custom rule to a test policy, then deletes it by priority
func TestDeleteCustomRuleByPriority(t *testing.T) {
	if testSinglePolicyId.Name == "" {
		t.Skipf("AZWAF_TEST_POLICY_ID not set")
	}

	s := session.New()
	p, err := getTestPolicy(s)
	require.NoError(t, err)

	numCustomRules := len(p.Properties.CustomRules.Rules)
	newCrOne, err := testSetup(s, p)
	require.NoError(t, err)
	require.NotNil(t, newCrOne)
	require.Len(t, p.Properties.CustomRules.Rules, numCustomRules+1)

	modified, err := policy.DeleteCustomRulesPrefixes(policy.DeleteCustomRulesPrefixesInput{
		Policy:      p,
		RID:         testSinglePolicyId,
		Name:        *newCrOne.Name,
		NameMatch:   nil,
		Priority:    int(*newCrOne.Priority),
		PrioritySet: true,
		MaxRules:    0,
		Debug:       false,
	})
	require.NoError(t, err)
	require.True(t, modified)

	// after deletion the policy should have the same number of rules as before the test
	require.Len(t, p.Properties.CustomRules.Rules, numCustomRules)
}

func TestUpdateCustomRulesPrefixes(t *testing.T) {
	if testSinglePolicyId.Name == "" {
		t.Skipf("AZWAF_TEST_POLICY_ID not set")
	}

	s := session.New()
	p, err := getTestPolicy(s)
	require.NoError(t, err)

	var priorityStart int
	empty, highestPriority := getHighestPriorityCustomRule(p)
	if !empty {
		priorityStart = int(highestPriority + 1)
	}

	ruleNamePrefix := policy.RuleNamePrefix(fmt.Sprintf("%s%s", integrationTestRulePrefix, testIdentifier))

	applyInput := &policy.UpdatePolicyCustomRulesIPMatchPrefixesInput{
		ResourceID: testSinglePolicyId,
		Policy:     p,
		Action:     armfrontdoor.ActionType("Block"),
		Addrs: []netip.Prefix{
			netip.MustParsePrefix("12.12.12.0/23"),
			netip.MustParsePrefix("13.13.13.13/32"),
		},
		MaxRules:       2,
		RuleNamePrefix: ruleNamePrefix,
		PriorityStart:  priorityStart,
	}

	modified, patch, err := policy.UpdatePolicyCustomRulesIPMatchPrefixes(*applyInput)
	require.NoError(t, err)
	require.NotEmpty(t, patch)
	require.True(t, modified)

	modified, err = policy.DeleteCustomRulesPrefixes(policy.DeleteCustomRulesPrefixesInput{
		RID:         testSinglePolicyId,
		Policy:      p,
		NameMatch:   regexp.MustCompile(fmt.Sprintf("^%s", ruleNamePrefix)),
		Priority:    0,
		PrioritySet: false,
		MaxRules:    0,
		Debug:       false,
	})
	require.NoError(t, err)
	require.True(t, modified)
}

func TestGetRuleSetDefinitionsMatchingPolicy(t *testing.T) {
	if subscriptionId == "" {
		t.Skipf("AZWAF_TEST_SUBSCRIPTION_ID not set")
	}

	p, err := policy.LoadPolicyFromFile("../policy/testdata/test-policy-one.json")
	require.NoError(t, err)

	s := session.New()

	// override policy id to use test subscription id that's checked by the function we're testing
	rid := config.ParseResourceID(*p.ID)
	rid.SubscriptionID = subscriptionId

	nRid := config.NewResourceID(subscriptionId, rid.ResourceGroup, "Microsoft.Network/frontdoorwebapplicationfirewallpolicies", rid.Name)
	p.ID = &nRid.Raw

	rsds, err := policy.GetRuleSetDefinitionsMatchingPolicy(s, &p)
	require.NoError(t, err)
	require.Len(t, rsds, 2)
	var foundCount int
	for _, rsd := range rsds {
		// output rsd meta data
		switch {
		case *rsd.Name == "Microsoft_DefaultRuleSet_1.1" &&
			*rsd.Properties.RuleSetType == "Microsoft_DefaultRuleSet" &&
			*rsd.Properties.RuleSetVersion == "1.1":
			foundCount++
		case *rsd.Name == "Microsoft_BotManagerRuleSet_1.0" &&
			*rsd.Properties.RuleSetType == "Microsoft_BotManagerRuleSet" &&
			*rsd.Properties.RuleSetVersion == "1.0":

			foundCount++
		}
	}

	require.Equal(t, 2, foundCount)
}

func getTestPolicy(s *session.Session) (p *armfrontdoor.WebApplicationFirewallPolicy, err error) {
	gpi := policy.GetPolicyInput{
		Session:  s,
		PolicyID: testSinglePolicyId,
	}

	gpo, err := gpi.GetPolicy()

	return gpo.Policy, err
}

func getHighestPriorityCustomRule(p *armfrontdoor.WebApplicationFirewallPolicy) (empty bool, h int32) {
	if len(p.Properties.CustomRules.Rules) == 0 {
		return true, 0
	}

	for _, cr := range p.Properties.CustomRules.Rules {
		if *cr.Priority > h {
			h = *cr.Priority
		}
	}

	return false, h
}

func addTestCustomRuleOneToPolicy(p *armfrontdoor.WebApplicationFirewallPolicy) (newCustomRule *armfrontdoor.CustomRule) {
	// get current highest priority
	empty, h := getHighestPriorityCustomRule(p)
	var newRulePriority int32
	if !empty {
		newRulePriority = h + 1
	}

	cr := armfrontdoor.CustomRule{
		Action: toPtr(armfrontdoor.ActionTypeBlock),
		MatchConditions: []*armfrontdoor.MatchCondition{{
			MatchValue:      []*string{toPtr("12.13.13.0/24")},
			MatchVariable:   toPtr(armfrontdoor.MatchVariableSocketAddr),
			Operator:        toPtr(armfrontdoor.OperatorIPMatch),
			NegateCondition: toPtr(false),
			Transforms:      nil,
		}},
		Priority:                   toPtr(newRulePriority),
		RuleType:                   toPtr(armfrontdoor.RuleTypeMatchRule),
		EnabledState:               toPtr(armfrontdoor.CustomRuleEnabledStateEnabled),
		Name:                       toPtr(fmt.Sprintf("%s%s", integrationTestRulePrefix, testIdentifier)),
		RateLimitDurationInMinutes: nil,
		RateLimitThreshold:         nil,
	}

	p.Properties.CustomRules.Rules = append(p.Properties.CustomRules.Rules, &cr)
	return &cr
}

func testSetup(s *session.Session, p *armfrontdoor.WebApplicationFirewallPolicy) (crOne *armfrontdoor.CustomRule, err error) {
	crOne = addTestCustomRuleOneToPolicy(p)
	return crOne, pushPolicy(s, testSinglePolicyId, p)
}

// func testTearDown(s *session.Session, p *armfrontdoor.WebApplicationFirewallPolicy) (crOne *armfrontdoor.CustomRule, err error) {
// 	policy.DeleteCustomRulesPrefixes() policy.DeleteCustomRulesCLIInput{
// 		PolicyID:     *p.ID,
// 		DryRun:       true,
// 		RID:          config.ResourceID{},
// 		Name:         *p.Name,
// 		NameMatch:    regexp.MustCompile(fmt.Sprintf("^%s", integrationTestRulePrefix)),
// 	}
// 	crOne = addTestCustomRuleOneToPolicy(p)
// 	return crOne, pushPolicy(s, testSinglePolicyId, p)
// }

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}

func pushPolicy(s *session.Session, r config.ResourceID, p *armfrontdoor.WebApplicationFirewallPolicy) error {
	return policy.PushPolicy(s, &policy.PushPolicyInput{
		Name:          r.Name,
		Subscription:  r.SubscriptionID,
		ResourceGroup: r.ResourceGroup,
		Policy:        *p,
		Debug:         true,
		Timeout:       30,
		Async:         false,
	})
}

func toPtr[T any](v T) *T {
	return &v
}
