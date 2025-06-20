package commands

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	policy "github.com/jonhadfield/azwaf/policy"
)

func CmdAdd(appVersion string) *cli.Command {
	return &cli.Command{
		Name:  "add",
		Usage: "add managed rule exclusions",
		Action: func(c *cli.Context) error {
			return cli.ShowAppHelp(c)
		},
		Subcommands: []*cli.Command{
			{
				Name:        "exclusion",
				UsageText:   "azwaf add exclusion [ --rule-set | --rule-group | --rule-id ] --variable=x --operator=x --selector=x [ <policy id> | <policy hash> ]",
				Description: fmt.Sprintf("add a managed rule exclusion to a rule, rule group, or rule set\n\nMatch Variables: %s\nMatch Operators: %s", strings.Join(policy.ValidRuleExclusionMatchVariables[:], ", "), strings.Join(policy.ValidRuleExclusionMatchOperators[:], ", ")),
				Aliases:     []string{"managed"},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  FlagDryRun,
						Usage: "show changes without applying", Aliases: []string{"d"},
					},
					&cli.BoolFlag{
						Name:  FlagShowDiff,
						Usage: "show difference between original and updated",
					},
					&cli.StringFlag{
						Name:    "rule-id",
						Usage:   "add exclusion to rule",
						Aliases: []string{"i"},
					},
					&cli.StringFlag{
						Name:  "rule-set",
						Usage: "add exclusion to rule set", Aliases: []string{"r"},
					},
					&cli.StringFlag{
						Name:  "rule-group",
						Usage: "add exclusion to rule group", Aliases: []string{"g"},
					},
					&cli.StringFlag{
						Name:    "match-variable",
						Usage:   "add exclusion for requests matching this variable",
						Aliases: []string{"v", "variable"}, Required: true,
					},
					&cli.StringFlag{
						Name:    "match-operator",
						Usage:   "add exclusion for requests with this operator",
						Aliases: []string{"o", "operator"}, Required: true,
					},
					&cli.StringFlag{
						Name:    "match-selector",
						Usage:   "add exclusion for requests with this selector",
						Aliases: []string{"s", "selector"}, Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					input := c.Args().First()

					if input == "" {
						// nolint:errcheck
						_ = cli.ShowSubcommandHelp(c)

						return fmt.Errorf("missing policy id / hash")
					}

					addManagedRuleExclusionCLIInput := policy.AddManagedRuleExclusionCLIInput{
						BaseCLIInput: policy.BaseCLIInput{
							AppVersion:     appVersion,
							AutoBackup:     c.Bool(FlagAutoBackup),
							Debug:          c.Bool("debug"),
							ConfigPath:     c.String(FlagConfig),
							SubscriptionID: c.String(FlagSubscriptionID),
							Quiet:          c.Bool("quiet"),
							DryRun:         c.Bool(FlagDryRun),
						},
						PolicyID:              input,
						RuleSet:               c.String("rule-set"),
						RuleGroup:             c.String("rule-group"),
						RuleID:                c.String("rule-id"),
						ExclusionRuleVariable: c.String("match-variable"),
						ExclusionRuleOperator: c.String("match-operator"),
						ExclusionRuleSelector: c.String("match-selector"),
						ShowDiff:              c.Bool(FlagShowDiff),
					}

					addManagedRuleExclusionCLIInput.DryRun = c.Bool(FlagDryRun)
					addManagedRuleExclusionCLIInput.AutoBackup = c.Bool(FlagAutoBackup)
					addManagedRuleExclusionCLIInput.AppVersion = appVersion

					return policy.AddManagedRuleExclusion(&addManagedRuleExclusionCLIInput)
				},
			},
		},
	}
}
