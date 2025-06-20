package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"

	policy "github.com/jonhadfield/azwaf/policy"
)

func CmdList() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "list front doors and policies",
		Action: func(c *cli.Context) error {
			return cli.ShowSubcommandHelp(c)
		},
		Subcommands: []*cli.Command{
			{
				Name:      "frontdoors",
				Usage:     "list front doors and associated policies in subscription",
				UsageText: "azwaf list frontdoors [--subscription=<AZURE_SUBSCRIPTION_ID>]",
				Aliases:   []string{"f"},
				Action: func(c *cli.Context) error {
					if c.String(FlagSubscriptionID) == "" {
						return fmt.Errorf("subscription-id required")
					}

					return policy.ListFrontDoors(c.String(FlagSubscriptionID))
				},
			},
			{
				Name:    "policies",
				Usage:   "list all policies in subscription",
				Aliases: []string{"p"},
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "full", Aliases: []string{"f"}, Usage: "include resource id in output"},
					&cli.IntFlag{Name: "top", Aliases: []string{"max"}, Usage: "number of policies to list", Value: policy.MaxPoliciesToFetch},
				},
				Action: func(c *cli.Context) error {
					input := policy.ListPoliciesInput{
						SubscriptionID: c.String(FlagSubscriptionID),
						Full:           c.Bool("full"),
						Max:            c.Int("top"),
					}

					if err := input.Validate(); err != nil {
						// nolint:errcheck
						_ = cli.ShowSubcommandHelp(c)

						return err
					}

					return policy.ListPolicies(input)
				},
			},
		},
	}
}
