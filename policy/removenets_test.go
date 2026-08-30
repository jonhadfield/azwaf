package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"
	"github.com/stretchr/testify/require"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/internal/azfakes"
)

// RemoveNets was deleted in v0.8.0 on the grounds that nothing in this
// repository called it. It had a downstream consumer, and it had no test —
// which is the only reason reachability analysis called it dead. These tests
// exist so that cannot happen again.

func mustPrefixes(t *testing.T, in ...string) []netip.Prefix {
	t.Helper()

	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		out = append(out, netip.MustParsePrefix(s))
	}

	return out
}

// The heart of the operation: existing minus requested, plus a per-address
// report saying which were actually there.
func TestBuildTrimmedNetworks(t *testing.T) {
	existing := mustPrefixes(t, "10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32")
	requested := mustPrefixes(t, "10.0.0.2/32", "192.0.2.9/32")

	trimmed, results := buildTrimmedNetworks(requested, existing, "policy-id")

	require.Equal(t, mustPrefixes(t, "10.0.0.1/32", "10.0.0.3/32"), trimmed,
		"the requested address is gone and the others survive")

	require.Len(t, results, 2)
	require.Equal(t, netip.MustParsePrefix("10.0.0.2/32"), results[0].Addr)
	require.True(t, results[0].Removed, "was present, so reported as removed")
	require.Equal(t, netip.MustParsePrefix("192.0.2.9/32"), results[1].Addr)
	require.False(t, results[1].Removed, "was never blocked, so reported as not removed")

	for _, r := range results {
		require.Equal(t, "policy-id", r.PolicyID)
	}
}

// Removing everything is legitimate and must not error; it leaves no prefixes.
func TestBuildTrimmedNetworksRemovingAll(t *testing.T) {
	existing := mustPrefixes(t, "10.0.0.1/32")

	trimmed, results := buildTrimmedNetworks(existing, existing, "p")

	require.Empty(t, trimmed)
	require.Len(t, results, 1)
	require.True(t, results[0].Removed)
}

func TestGetNetsToRemove(t *testing.T) {
	t.Run("errors when nothing is supplied", func(t *testing.T) {
		_, err := getNetsToRemove("", nil)
		require.ErrorContains(t, err, "no ips to unblock provided")
	})

	t.Run("passes through addresses given directly", func(t *testing.T) {
		out, err := getNetsToRemove("", mustPrefixes(t, "10.0.0.1/32"))
		require.NoError(t, err)
		require.Len(t, out, 1)
	})

	t.Run("combines a file with addresses given directly", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nets.txt")
		require.NoError(t, os.WriteFile(path, []byte("10.0.0.7/32\n10.0.0.8/32\n"), 0o600))

		out, err := getNetsToRemove(path, mustPrefixes(t, "10.0.0.9/32"))
		require.NoError(t, err)
		require.Len(t, out, 3, "two from the file plus the one passed in")
	})

	t.Run("errors on an unreadable path", func(t *testing.T) {
		_, err := getNetsToRemove(filepath.Join(t.TempDir(), "missing.txt"), nil)
		require.ErrorContains(t, err, "failed to load IPs from path")
	})
}

// The regenerated rules reuse the lowest existing priority for the prefix, so
// unblocking does not silently reorder a policy.
func TestGetLowestPriority(t *testing.T) {
	rules := []*armfrontdoor.CustomRule{
		{Name: toPtr("Other"), Priority: toPtr(int32(5))},
		{Name: toPtr("BlockNets1234"), Priority: toPtr(int32(1234))},
		{Name: toPtr("BlockNets500"), Priority: toPtr(int32(500))},
		{Name: toPtr("BlockNets6000"), Priority: toPtr(int32(6000))},
	}

	require.Equal(t, int32(500), getLowestPriority(rules, "BlockNets"))
}

// Nil entries and nil fields must not bring the process down.
func TestGetLowestPriorityToleratesNils(t *testing.T) {
	rules := []*armfrontdoor.CustomRule{
		nil,
		{Name: nil, Priority: toPtr(int32(1))},
		{Name: toPtr("BlockNets1"), Priority: nil},
		{Name: toPtr("BlockNets2"), Priority: toPtr(int32(300))},
	}

	require.NotPanics(t, func() {
		require.Equal(t, int32(300), getLowestPriority(rules, "BlockNets"))
	})
}

func TestRemoveNetsGuards(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		_, err := RemoveNets(nil)
		require.ErrorContains(t, err, "input cannot be nil")
	})

	t.Run("nil rule type", func(t *testing.T) {
		_, err := RemoveNets(&RemoveNetsInput{})
		require.ErrorContains(t, err, "rule type cannot be nil")
	})

	t.Run("nil apply input", func(t *testing.T) {
		_, err := ApplyRemoveAddrs(nil, nil)
		require.ErrorContains(t, err, "input cannot be nil")
	})
}

// Rules not carrying the prefix are left alone; only the prefixed ones are
// regenerated from the trimmed set.
func TestMergeCustomRulesPreservesUnrelatedRules(t *testing.T) {
	p := &armfrontdoor.WebApplicationFirewallPolicy{
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			CustomRules: &armfrontdoor.CustomRuleList{
				Rules: []*armfrontdoor.CustomRule{
					{Name: toPtr("KeepMe"), Priority: toPtr(int32(10))},
					{Name: toPtr("BlockNets100"), Priority: toPtr(int32(100))},
				},
			},
		},
	}

	merged, err := mergeCustomRules(p, mustPrefixes(t, "10.0.0.1/32"), &ApplyRemoveNetsInput{
		MatchPrefix: "BlockNets",
		Action:      toPtr(armfrontdoor.ActionTypeBlock),
		RuleType:    toPtr(armfrontdoor.RuleTypeMatchRule),
	})
	require.NoError(t, err)

	var names []string
	for _, r := range merged {
		names = append(names, *r.Name)
	}

	require.Contains(t, names, "KeepMe", "an unrelated rule must survive untouched")
	require.NotEmpty(t, merged)
}

// End to end over the fake Azure endpoints: the shape a downstream /unblock
// endpoint uses. The policy is fetched, trimmed and pushed for real through the
// SDK's own serialisation and poller code.
func TestRemoveNetsEndToEndAgainstFakes(t *testing.T) {
	blocked := []*armfrontdoor.CustomRule{{
		Name:         toPtr("BlockNets100"),
		Priority:     toPtr(int32(100)),
		RuleType:     toPtr(armfrontdoor.RuleTypeMatchRule),
		Action:       toPtr(armfrontdoor.ActionTypeBlock),
		EnabledState: toPtr(armfrontdoor.CustomRuleEnabledStateEnabled),
		MatchConditions: []*armfrontdoor.MatchCondition{{
			MatchVariable:   toPtr(armfrontdoor.MatchVariableSocketAddr),
			Operator:        toPtr(armfrontdoor.OperatorIPMatch),
			NegateCondition: toPtr(false),
			MatchValue:      []*string{toPtr("10.0.0.1/32"), toPtr("10.0.0.2/32")},
		}},
	}}

	pol := fdPolicyForFakeTest()
	pol.Properties.CustomRules = &armfrontdoor.CustomRuleList{Rules: blocked}

	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", pol)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	parsed := config.ParseResourceID(rid)

	results, err := ApplyRemoveAddrs(s, &ApplyRemoveNetsInput{
		RID:         parsed,
		MatchPrefix: "BlockNets",
		Action:      toPtr(armfrontdoor.ActionTypeBlock),
		RuleType:    toPtr(armfrontdoor.RuleTypeMatchRule),
		Addrs:       mustPrefixes(t, "10.0.0.1/32", "203.0.113.1/32"),
	})
	require.NoError(t, err)
	require.Len(t, results, 2)

	require.True(t, results[0].Removed, "10.0.0.1/32 was blocked, so it is removed")
	require.False(t, results[1].Removed, "203.0.113.1/32 was never blocked")

	// the surviving address must still be blocked in the stored policy
	stored, ok := st.FrontDoorPolicy("rg-one", "fd-one")
	require.True(t, ok)

	var remaining []string
	for _, cr := range policyCustomRules(&stored) {
		for _, mc := range cr.MatchConditions {
			for _, mv := range mc.MatchValue {
				remaining = append(remaining, *mv)
			}
		}
	}

	require.Contains(t, remaining, "10.0.0.2/32", "the address that was not unblocked must survive")
	require.NotContains(t, remaining, "10.0.0.1/32", "the unblocked address must be gone")
}
