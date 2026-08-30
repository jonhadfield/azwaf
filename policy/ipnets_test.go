package policy

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"
	"github.com/stretchr/testify/require"
)

func ipMatchCondition(negate bool, nets ...string) *armfrontdoor.MatchCondition {
	vals := make([]*string, 0, len(nets))
	for i := range nets {
		vals = append(vals, &nets[i])
	}

	return &armfrontdoor.MatchCondition{
		MatchVariable:   toPtr(armfrontdoor.MatchVariableSocketAddr),
		Operator:        toPtr(armfrontdoor.OperatorIPMatch),
		NegateCondition: toPtr(negate),
		MatchValue:      vals,
	}
}

func geoMatchCondition() *armfrontdoor.MatchCondition {
	return &armfrontdoor.MatchCondition{
		MatchVariable:   toPtr(armfrontdoor.MatchVariableSocketAddr),
		Operator:        toPtr(armfrontdoor.OperatorGeoMatch),
		NegateCondition: toPtr(false),
		MatchValue:      []*string{toPtr("GB")},
	}
}

// The two collectors walk the same match conditions and split them the same
// way. They differ in what they do with a condition that is not an IP match:
// one skips it, the other refuses the whole rule.
func TestIPNetCollectorsSplitPositiveAndNegative(t *testing.T) {
	cr := &armfrontdoor.CustomRule{
		Name: toPtr("R"),
		MatchConditions: []*armfrontdoor.MatchCondition{
			ipMatchCondition(false, "10.0.0.0/24", "10.0.1.0/24"),
			ipMatchCondition(true, "10.0.0.5/32"),
		},
	}

	pos, neg, err := getIPNetsForRuleIPMatchConditions(cr)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.1.0/24")}, pos)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")}, neg)

	pos, neg, err = getIPNetsForPrefix([]*armfrontdoor.CustomRule{cr}, toPtr(armfrontdoor.ActionTypeBlock))
	require.NoError(t, err)
	require.Len(t, pos, 2)
	require.Len(t, neg, 1)
}

func TestIPNetCollectorsDifferOnUnsupportedConditions(t *testing.T) {
	cr := &armfrontdoor.CustomRule{
		Name: toPtr("R"),
		MatchConditions: []*armfrontdoor.MatchCondition{
			geoMatchCondition(),
			ipMatchCondition(false, "10.0.0.0/24"),
		},
	}

	// the single-rule collector skips what it cannot handle
	pos, _, err := getIPNetsForRuleIPMatchConditions(cr)
	require.NoError(t, err)
	require.Len(t, pos, 1, "the geo condition is skipped, the ip one is kept")

	// the multi-rule collector refuses the rule outright
	_, _, err = getIPNetsForPrefix([]*armfrontdoor.CustomRule{cr}, toPtr(armfrontdoor.ActionTypeBlock))
	require.ErrorContains(t, err, "does not match constraints")
}

func TestGetIPNetsForPrefixRequiresAnAction(t *testing.T) {
	_, _, err := getIPNetsForPrefix(nil, nil)
	require.ErrorContains(t, err, "action cannot be nil")
}

// A match condition with no negate flag set must not bring the process down.
func TestIPNetCollectorsTolerateNilNegateCondition(t *testing.T) {
	cr := &armfrontdoor.CustomRule{
		Name: toPtr("R"),
		MatchConditions: []*armfrontdoor.MatchCondition{
			{
				MatchVariable:   toPtr(armfrontdoor.MatchVariableSocketAddr),
				Operator:        toPtr(armfrontdoor.OperatorIPMatch),
				NegateCondition: nil,
				MatchValue:      []*string{toPtr("10.0.0.0/24")},
			},
		},
	}

	require.NotPanics(t, func() {
		pos, neg, err := getIPNetsForRuleIPMatchConditions(cr)
		require.NoError(t, err)
		require.Len(t, pos, 1, "an absent negate flag means not negated")
		require.Empty(t, neg)
	})
}

// prepareMatchConditions refuses a negated set large enough to leave no room
// for the positive one. rebuildIPMatchConditions had no such guard.
func TestPrepareMatchConditionsRejectsOversizedNegatedSet(t *testing.T) {
	negated := make([]netip.Prefix, 0, 600)
	for i := range 600 {
		negated = append(negated, netip.MustParsePrefix(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}).String()+"/32"))
	}

	_, _, err := prepareMatchConditions(GenCustomRulesFromIPNetsInput{
		PositiveMatchNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		NegativeMatchNets: negated,
	})
	require.ErrorContains(t, err, "cannot exceed 599")
}

// rebuildIPMatchConditions shares that guard now. It previously had none: with
// the negated set at the limit the positive budget fell to zero, and since the
// chunker only flushes early when a chunk reaches its budget, every positive
// net landed in a single condition well over Azure's per-condition maximum.
func TestRebuildIPMatchConditionsRejectsOversizedNegatedSet(t *testing.T) {
	negated := make([]netip.Prefix, 0, MaxIPMatchValues)
	for i := range MaxIPMatchValues {
		negated = append(negated, netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/32", i/256, i%256)))
	}

	positive := make([]netip.Prefix, 0, 2000)
	for i := range 2000 {
		positive = append(positive, netip.MustParsePrefix(fmt.Sprintf("172.%d.%d.0/32", i/256, i%256)))
	}

	_, _, err := rebuildIPMatchConditions(&armfrontdoor.CustomRule{Name: toPtr("R")}, positive, negated)
	require.ErrorContains(t, err, "cannot exceed 599",
		"without the guard this returned one match condition holding all 2000 positive values")
}

// A negated set that leaves room still chunks the positive one normally.
func TestRebuildIPMatchConditionsChunksWithinBudget(t *testing.T) {
	negated := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}

	positive := make([]netip.Prefix, 0, 1000)
	for i := range 1000 {
		positive = append(positive, netip.MustParsePrefix(fmt.Sprintf("172.%d.%d.0/32", i/256, i%256)))
	}

	pos, neg, err := rebuildIPMatchConditions(&armfrontdoor.CustomRule{Name: toPtr("R")}, positive, negated)
	require.NoError(t, err)
	require.Len(t, neg, 1)
	require.Len(t, pos, 2, "1000 nets at 599 per condition needs two conditions")

	for _, mc := range pos {
		require.LessOrEqual(t, len(mc.MatchValue), MaxIPMatchValues-len(neg[0].MatchValue))
	}
}
