package commands

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	policy "github.com/jonhadfield/azwaf/policy"
)

// deleteCmd builds a *cli.Command carrying the flags the delete subcommands
// read, plus the given positional argument.
//
// v2 allowed a Context to be assembled straight from a flag.FlagSet. v3 has no
// such constructor, so the flags are declared on a throwaway command and parsed
// by actually running it, which exercises the real parser rather than a
// hand-built flag set.
func deleteCmd(t *testing.T, args map[string]string, positional string) *cli.Command {
	t.Helper()

	var flags []cli.Flag

	for _, name := range []string{
		"name", "priority", FlagConfig, FlagSubscriptionID,
		"rule-set", "rule-group", "rule-id",
		"match-variable", "match-operator", "match-selector",
	} {
		flags = append(flags, &cli.StringFlag{Name: name})
	}

	for _, name := range []string{FlagDryRun, FlagShowDiff, FlagAutoBackup, "debug", "quiet"} {
		flags = append(flags, &cli.BoolFlag{Name: name})
	}

	var captured *cli.Command

	root := &cli.Command{
		Name:  "test",
		Flags: flags,
		Action: func(_ context.Context, cmd *cli.Command) error {
			captured = cmd

			return nil
		},
	}

	argv := []string{"test"}
	for k, v := range args {
		argv = append(argv, "--"+k, v)
	}

	argv = append(argv, positional)

	require.NoError(t, root.Run(context.Background(), argv))
	require.NotNil(t, captured)

	return captured
}

// An alias contains no "/". Both delete subcommands used to run
// policy.ValidateResourceID on the raw argument, which rejected aliases before
// they could be looked up in the config file. The name must now reach the input
// untouched, for resolution further down.
func TestNewDeleteCustomRulesInputPassesAliasThrough(t *testing.T) {
	in, err := newDeleteCustomRulesInput(deleteCmd(t, map[string]string{
		"name":             "^DropMe$",
		FlagConfig:         "/tmp/azwaf-config.yaml",
		FlagSubscriptionID: "10000000-0000-0000-0000-000000000001",
	}, "prod-waf"), "v-test")

	require.NoError(t, err)
	require.Equal(t, "prod-waf", in.PolicyID)

	// guard: this is the check that used to run here. It rejects aliases, so
	// re-introducing it would break `delete` for alias users all over again.
	require.Error(t, policy.ValidateResourceID("prod-waf", false))

	// ConfigPath must be populated or the alias lookup has no file to read
	require.Equal(t, "/tmp/azwaf-config.yaml", in.ConfigPath)
	require.Equal(t, "10000000-0000-0000-0000-000000000001", in.SubscriptionID)
}

func TestNewDeleteManagedRuleExclusionInputPassesAliasThrough(t *testing.T) {
	in, err := newDeleteManagedRuleExclusionInput(deleteCmd(t, map[string]string{
		"rule-set":         "Microsoft_DefaultRuleSet_2.1",
		"match-variable":   "RequestHeaderNames",
		"match-operator":   "Equals",
		"match-selector":   "User-Agent",
		FlagConfig:         "/tmp/azwaf-config.yaml",
		FlagSubscriptionID: "10000000-0000-0000-0000-000000000001",
	}, "prod-waf"), "v-test")

	require.NoError(t, err)
	require.Equal(t, "prod-waf", in.PolicyID)
	// this path previously never populated ConfigPath at all
	require.Equal(t, "/tmp/azwaf-config.yaml", in.ConfigPath)
	require.Equal(t, "10000000-0000-0000-0000-000000000001", in.SubscriptionID)
}

// A hash without a subscription id used to be rejected in the CLI; that check
// now lives in GetWAFPolicyResourceID, so the builder must not pre-empt it.
func TestNewDeleteInputsPassHashThroughWithoutSubscription(t *testing.T) {
	crIn, err := newDeleteCustomRulesInput(
		deleteCmd(t, map[string]string{"name": "^DropMe$"}, "0e1b2c3d"), "v-test")
	require.NoError(t, err)
	require.Equal(t, "0e1b2c3d", crIn.PolicyID)

	mreIn, err := newDeleteManagedRuleExclusionInput(
		deleteCmd(t, map[string]string{"rule-set": "Microsoft_DefaultRuleSet_2.1"}, "0e1b2c3d"), "v-test")
	require.NoError(t, err)
	require.Equal(t, "0e1b2c3d", mreIn.PolicyID)
}

func TestNewDeleteInputsRejectMissingArguments(t *testing.T) {
	_, err := newDeleteCustomRulesInput(deleteCmd(t, map[string]string{"name": "^DropMe$"}, ""), "v-test")
	require.ErrorContains(t, err, "missing policy id")

	// name and priority both unset
	_, err = newDeleteCustomRulesInput(deleteCmd(t, nil, "prod-waf"), "v-test")
	require.ErrorContains(t, err, "name and/or priority")

	_, err = newDeleteManagedRuleExclusionInput(deleteCmd(t, nil, ""), "v-test")
	require.ErrorContains(t, err, "missing policy id")
}

// A global --debug flag is now registered in cmd/azwaf/main.go. It was read by
// six commands before that, but never declared, so c.Bool("debug") was always
// false and the debug plumbing behind it was unreachable.
func TestNewDeleteInputsPropagateDebug(t *testing.T) {
	crIn, err := newDeleteCustomRulesInput(
		deleteCmd(t, map[string]string{"name": "^DropMe$", "debug": "true"}, "prod-waf"), "v-test")
	require.NoError(t, err)
	require.True(t, crIn.Debug)

	mreIn, err := newDeleteManagedRuleExclusionInput(
		deleteCmd(t, map[string]string{"rule-set": "Microsoft_DefaultRuleSet_2.1", "debug": "true"}, "prod-waf"), "v-test")
	require.NoError(t, err)
	require.True(t, mreIn.Debug)

	// and default to off
	offIn, err := newDeleteCustomRulesInput(deleteCmd(t, map[string]string{"name": "^DropMe$"}, "prod-waf"), "v-test")
	require.NoError(t, err)
	require.False(t, offIn.Debug)
}
