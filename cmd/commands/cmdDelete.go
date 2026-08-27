package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"

	policy "github.com/jonhadfield/azwaf/policy"
)

func CmdDelete(versionOutput string) *cli.Command {
	return &cli.Command{
		Name:  "delete",
		Usage: "delete custom and managed rules from a policy",
		Action: func(c *cli.Context) error {
			return cli.ShowAppHelp(c)
		},
		Subcommands: []*cli.Command{
			{
				Name:    "managed-rule-exclusion",
				Usage:   "azwaf get managed-rule-exclusion [ --rule-set | --rule-group | --rule-id ] --match-variable=x --match-operator=x --match-selector=x",
				Aliases: []string{"m", "mre", "exclusion"},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  FlagDryRun,
						Usage: "Show changes without applying", Aliases: []string{"d"},
					},
					&cli.BoolFlag{
						Name:  FlagShowDiff,
						Usage: "Show differences",
					},
					&cli.StringFlag{
						Name:  "rule-set",
						Usage: "get managed ruleset exclusions matching this name <type>_<version>",
					},
					&cli.StringFlag{
						Name:  "rule-group",
						Usage: "get managed rule group exclusions matching this name",
					},
					&cli.StringFlag{
						Name:  "rule-id",
						Usage: "get managed rule exclusions matching this id",
					},
					// we can be specific more specific and Get only entries within the rule exclusion
					&cli.StringFlag{
						Name:    "match-variable",
						Usage:   "get entries from rule matching this variable",
						Aliases: []string{"v", "variable"}, Required: true,
					},
					&cli.StringFlag{
						Name:    "match-operator",
						Usage:   "get entries from rule also matching this operator",
						Aliases: []string{"o", "operator"}, Required: true,
					},
					&cli.StringFlag{
						Name:    "match-selector",
						Usage:   "get entries from rule also matching this selector",
						Aliases: []string{"s", "selector"}, Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					in, err := newDeleteManagedRuleExclusionInput(c, versionOutput)
					if err != nil {
						// nolint:errcheck
						_ = cli.ShowSubcommandHelp(c)

						return err
					}

					return policy.DeleteManagedRuleExclusion(in)
				},
			},
			{
				Name:        "custom-rule",
				Aliases:     []string{"c", "cr"},
				Usage:       "Get custom-rules",
				Description: "azwaf [-dcr | --Gete-custom-rule] [-p | --priority <rulepriority>] [-n | --name <rulename>] <policy-resource-id>",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: FlagDryRun, Usage: "Show changes without applying", Aliases: []string{"d"}},
					&cli.StringFlag{Name: "name", Usage: "custom-rule name (regex match)", Aliases: []string{"n"}},
					&cli.StringFlag{Name: "priority", Usage: "custom-rule priority", Aliases: []string{"p"}},
				},
				Action: func(c *cli.Context) error {
					in, err := newDeleteCustomRulesInput(c, versionOutput)
					if err != nil {
						// nolint:errcheck
						_ = cli.ShowSubcommandHelp(c)

						return err
					}

					return policy.DeleteCustomRulesCLI(in)
				},
			},
		},
	}
}

// newDeleteCustomRulesInput builds the input for `delete custom-rule` from the
// CLI context.
//
// The policy name is deliberately passed through untouched: aliases, hashes and
// full resource ids are all resolved (and validated) later by
// policy.GetWAFPolicyResourceID. Validating the raw argument here would reject
// aliases, which contain no "/".
func newDeleteCustomRulesInput(c *cli.Context, versionOutput string) (*policy.DeleteCustomRulesCLIInput, error) {
	if c.String("name") == "" && c.String("priority") == "" {
		return nil, fmt.Errorf("name and/or priority must be defined")
	}

	input := c.Args().First()
	if input == "" {
		return nil, fmt.Errorf("missing policy id / hash")
	}

	return &policy.DeleteCustomRulesCLIInput{
		BaseCLIInput: baseCLIInput(c, versionOutput),
		PolicyID:     input,
		Name:         c.String("name"),
		Priority:     c.String("priority"),
	}, nil
}

// newDeleteManagedRuleExclusionInput builds the input for
// `delete managed-rule-exclusion` from the CLI context. See the note on
// newDeleteCustomRulesInput about not validating the raw policy name here.
func newDeleteManagedRuleExclusionInput(c *cli.Context, versionOutput string) (*policy.DeleteManagedRuleExclusionCLIInput, error) {
	input := c.Args().First()
	if input == "" {
		return nil, fmt.Errorf("missing policy id / hash")
	}

	return &policy.DeleteManagedRuleExclusionCLIInput{
		BaseCLIInput:          baseCLIInput(c, versionOutput),
		PolicyID:              input,
		RuleSet:               c.String("rule-set"),
		RuleGroup:             c.String("rule-group"),
		RuleID:                c.String("rule-id"),
		ShowDiff:              c.Bool(FlagShowDiff),
		ExclusionRuleVariable: c.String("match-variable"),
		ExclusionRuleOperator: c.String("match-operator"),
		ExclusionRuleSelector: c.String("match-selector"),
	}, nil
}

// baseCLIInput collects the global flags shared by every command.
func baseCLIInput(c *cli.Context, versionOutput string) policy.BaseCLIInput {
	return policy.BaseCLIInput{
		AppVersion:     versionOutput,
		AutoBackup:     c.Bool(FlagAutoBackup),
		Debug:          c.Bool("debug"),
		ConfigPath:     c.String(FlagConfig),
		SubscriptionID: c.String(FlagSubscriptionID),
		Quiet:          c.Bool("quiet"),
		DryRun:         c.Bool(FlagDryRun),
	}
}
