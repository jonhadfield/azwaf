package commands

import (
	"fmt"

	. "github.com/jonhadfield/azwaf/policy"
	"github.com/urfave/cli/v2"
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
					input := c.Args().First()
					if input != "" {
						// TODO: check if extended or not and allow specification of custom-rule?
						if err := ValidateResourceID(input, false); err != nil {
							// nolint:errcheck
							_ = cli.ShowSubcommandHelp(c)

							return err
						}

						subID := c.String(FlagSubscriptionID)
						if IsRIDHash(input) && subID == "" {
							// nolint:errcheck
							_ = cli.ShowSubcommandHelp(c)

							return fmt.Errorf("using a policy hash requires a subscription id")
						}

						dmre := DeleteManagedRuleExclusionCLIInput{
							SubscriptionID:        subID,
							PolicyID:              input,
							RuleSet:               c.String("rule-set"),
							RuleGroup:             c.String("rule-group"),
							RuleID:                c.String("rule-id"),
							ShowDiff:              c.Bool(FlagShowDiff),
							ExclusionRuleVariable: c.String("match-variable"),
							ExclusionRuleOperator: c.String("match-operator"),
							ExclusionRuleSelector: c.String("match-selector"),
						}

						dmre.AutoBackup = c.Bool(FlagAutoBackup)
						dmre.DryRun = c.Bool(FlagDryRun)
						dmre.AppVersion = versionOutput

						return DeleteManagedRuleExclusion(&dmre)
					}

					// nolint:errcheck
					_ = cli.ShowSubcommandHelp(c)

					return fmt.Errorf("invalid usage")
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
					if c.String("name") == "" && c.String("priority") == "" {
						// nolint:errcheck
						_ = cli.ShowSubcommandHelp(c)

						return fmt.Errorf("name and/or priority must be defined")
					}

					input := c.Args().First()
					if input != "" {
						// TODO: check if extended or not and allow specification of custom-rule?
						if err := ValidateResourceID(input, false); err != nil {
							return cli.ShowSubcommandHelp(c)
						}

						return DeleteCustomRulesCLI(&DeleteCustomRulesCLIInput{
							BaseCLIInput: BaseCLIInput{
								AppVersion:     versionOutput,
								AutoBackup:     c.Bool(FlagAutoBackup),
								Debug:          c.Bool("debug"),
								ConfigPath:     c.String(FlagConfig),
								SubscriptionID: c.String(FlagSubscriptionID),
								Quiet:          c.Bool("quiet"),
								DryRun:         c.Bool(FlagDryRun),
							},
							PolicyID: input,
							Name:     c.String("name"),
							Priority: c.String("priority"),
						})
					}

					// nolint:errcheck
					_ = cli.ShowSubcommandHelp(c)

					return fmt.Errorf("invalid usage")
				},
			},
		},
	}
}
