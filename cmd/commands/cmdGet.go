package commands

import (
	. "github.com/jonhadfield/azwaf/policy"
	"github.com/urfave/cli/v2"
)

func CmdGet() *cli.Command {
	return &cli.Command{
		Name:  "get",
		Usage: "get policy data",
		Action: func(c *cli.Context) error {
			return cli.ShowAppHelp(c)
		},
		Subcommands: []*cli.Command{
			{
				Name:    "policy",
				Usage:   "get policy using resource id",
				Aliases: []string{"p"},
				Action: func(c *cli.Context) error {
					// get custom rule match-value field using format "<policy id>|<rule-name>"
					input := c.Args().First()

					return PrintPolicy(input, c.String(FlagSubscriptionID), c.String(FlagConfig))
				},
			},
			{
				Name:    "custom-rule",
				Usage:   "get custom-rule using format \"<policy id>|<rule-name>\"",
				Aliases: []string{"c"},
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Usage: "save custom-rule to path"},
				},
				Action: func(c *cli.Context) error {
					// get custom rule match-value field using format "<policy id>|<rule-name>"
					input := c.Args().First()

					return PrintPolicyCustomRule(c.String(FlagSubscriptionID), input, c.String(FlagConfig))
				},
			},
		},
	}
}
