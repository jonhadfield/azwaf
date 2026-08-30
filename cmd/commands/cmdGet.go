package commands

import (
	"context"

	"github.com/urfave/cli/v3"

	policy "github.com/jonhadfield/azwaf/policy"
)

func CmdGet() *cli.Command {
	return &cli.Command{
		Name:  "get",
		Usage: "get policy data",
		Action: func(_ context.Context, c *cli.Command) error {
			return cli.DefaultShowRootCommandHelp(c)
		},
		Commands: []*cli.Command{
			{
				Name:    "policy",
				Usage:   "get policy using resource id",
				Aliases: []string{"p"},
				Action: func(_ context.Context, c *cli.Command) error {
					// get custom rule match-value field using format "<policy id>|<rule-name>"
					input := c.Args().First()

					return policy.PrintPolicy(input, c.String(FlagSubscriptionID), c.String(FlagConfig))
				},
			},
			{
				Name:    "custom-rule",
				Usage:   "get custom-rule using format \"<policy id>|<rule-name>\"",
				Aliases: []string{"c"},
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Usage: "save custom-rule to path"},
				},
				Action: func(_ context.Context, c *cli.Command) error {
					// get custom rule match-value field using format "<policy id>|<rule-name>"
					input := c.Args().First()

					return policy.PrintPolicyCustomRule(policy.PrintPolicyCustomRuleInput{
						SubscriptionID: c.String(FlagSubscriptionID),
						ExtendedID:     input,
						ConfigPath:     c.String(FlagConfig),
						OutputPath:     c.String("output"),
						Quiet:          c.Bool("quiet"),
					})
				},
			},
		},
	}
}
