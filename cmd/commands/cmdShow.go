package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"

	. "github.com/jonhadfield/azwaf/policy"
)

func CmdShow() *cli.Command {
	return &cli.Command{
		Name:  "show",
		Usage: "show policy",
		Action: func(c *cli.Context) error {
			// nolint:errcheck
			_ = cli.ShowAppHelp(c)

			return nil
		},
		Subcommands: []*cli.Command{
			{
				Name:  "policy",
				Usage: "azwaf show policy <policy resource id>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rule-name", Usage: "filter by specific rule", Hidden: true},
					&cli.BoolFlag{Name: "show-full", Usage: "show all match conditions"},
					&cli.BoolFlag{Name: "custom-only", Usage: "show custom rules only", Value: false, Aliases: []string{"custom"}},
					&cli.BoolFlag{Name: "managed-only", Usage: "show managed rules only", Value: false, Aliases: []string{"managed"}},
					&cli.BoolFlag{Name: "stats", Usage: "show stats", Value: false},
					&cli.BoolFlag{Name: "shadows", Usage: "show shadows", Value: false},
				},
				Action: func(c *cli.Context) error {
					config := ShowPolicyInput{
						ConfigPath:     c.String("config"),
						SubscriptionID: c.String("subscription-id"),
						PolicyID:       c.Args().First(),
						Full:           c.Bool("show-full"),
						Custom:         c.Bool("custom"),
						Managed:        c.Bool("managed"),
						Stats:          c.Bool("stats"),
						Shadows:        c.Bool("shadows"),
					}

					if err := config.Validate(); err != nil {
						// nolint:errcheck
						if serr := cli.ShowSubcommandHelp(c); serr != nil {
							return serr
						}

						return err
					}

					return ShowPolicy(config)
				},
			},
			{
				Name:    "managed-rule-exclusions",
				Usage:   "azwaf show managed-rule-exclusions [ --rule-id | --rule-set | --rule-group ] [ <policy resource id> | <policy hash> ]",
				Aliases: []string{"m", "managed", "exclusions", "exclusion"},
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rule-id", Usage: "show exclusions for specific rule", Aliases: []string{"id", "rule"}},
					&cli.StringFlag{Name: "rule-set", Usage: "show exclusions for specific rule-set", Aliases: []string{"ruleset"}},
					&cli.StringFlag{Name: "rule-group", Usage: "show exclusions for specific group", Aliases: []string{"group"}},
					&cli.BoolFlag{Name: "shadows", Usage: "show rule and rule group exclusions that shadow wider scopes", Value: false},
				},
				Action: func(c *cli.Context) error {
					policyID := c.Args().First()

					if policyID == "" {
						// nolint:errcheck
						_ = cli.ShowSubcommandHelp(c)

						return fmt.Errorf("policy id must be specified")
					}

					input := ShowExclusionsCLIInput{
						BaseCLIInput: BaseCLIInput{
							AutoBackup:     c.Bool("auto-backup"),
							Debug:          c.Bool("debug"),
							ConfigPath:     c.String("config"),
							SubscriptionID: c.String("subscription-id"),
							Quiet:          c.Bool("quiet"),
							DryRun:         c.Bool("dry-run"),
						},
						PolicyID:  policyID,
						RuleSet:   c.String("rule-set"),
						RuleGroup: c.String("rule-group"),
						RuleID:    c.String("rule-id"),
						Shadows:   c.Bool("shadows"),
					}
					if err := input.Validate(); err != nil {
						return err
					}

					return ShowExclusions(&input)
				},
			},
		},
	}
}
