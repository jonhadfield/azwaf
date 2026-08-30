package commands

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	policy "github.com/jonhadfield/azwaf/policy"
)

func CmdList() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "list front doors and policies",
		Action: func(_ context.Context, c *cli.Command) error {
			return cli.DefaultShowSubcommandHelp(c)
		},
		Commands: []*cli.Command{
			{
				Name:      "frontdoors",
				Usage:     "list front doors and associated policies in subscription",
				UsageText: "azwaf list frontdoors [--subscription=<AZURE_SUBSCRIPTION_ID>]",
				Aliases:   []string{"f"},
				Action: func(_ context.Context, c *cli.Command) error {
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
				Action: func(_ context.Context, c *cli.Command) error {
					input := policy.ListPoliciesInput{
						SubscriptionID: c.String(FlagSubscriptionID),
						Full:           c.Bool("full"),
						Max:            c.Int("top"),
					}

					if err := input.Validate(); err != nil {
						// nolint:errcheck
						_ = cli.DefaultShowSubcommandHelp(c)

						return err
					}

					return policy.ListPolicies(input)
				},
			},
		},
	}
}
