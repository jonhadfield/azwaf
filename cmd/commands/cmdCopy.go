package commands

import (
	. "github.com/jonhadfield/azwaf/policy"
	"github.com/urfave/cli/v2"
)

func CmdCopy(versionOutput string) *cli.Command {
	return &cli.Command{
		Name:        "copy",
		Usage:       "copy custom and/or managed rules between policies",
		Description: "both custom and managed rules are copied by default, but can be limited to one with the relevant flag.\nnote: use of hashes limited to current subscription.",
		UsageText:   "azwaf copy --source --target [<options>]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "source", Usage: "source policy resource id or hash", Aliases: []string{"s", "src"}, Required: true},
			&cli.StringFlag{Name: "target", Usage: "target policy resource id or hash", Aliases: []string{"t"}, Required: true},
			&cli.BoolFlag{Name: "custom-rules", Usage: "copy custom rules only", Aliases: []string{"custom", "c"}},
			&cli.BoolFlag{Name: "managed-rules", Usage: "copy managed rules only", Aliases: []string{"managed", "m"}},
			&cli.BoolFlag{Name: "show-diff", Usage: "show policy differences", Aliases: []string{"show", "diff"}},
			&cli.BoolFlag{Name: "dry-run", Usage: "don't push generated policy", Aliases: []string{"d"}},
			&cli.BoolFlag{Name: "async", Usage: "push resulting policy without waiting for completion", Aliases: []string{"a"}},
		},
		Action: func(c *cli.Context) error {
			copyRulesInput := CopyRulesInput{
				BaseCLIInput: BaseCLIInput{
					AppVersion:     versionOutput,
					AutoBackup:     c.Bool("auto-backup"),
					Debug:          c.Bool("debug"),
					ConfigPath:     c.String("config"),
					SubscriptionID: c.String("subscription-id"),
					Quiet:          c.Bool("quiet"),
					DryRun:         c.Bool("dry-run"),
				},
				Source:           c.String("source"),
				Target:           c.String("target"),
				ManagedRulesOnly: c.Bool("managed-rules"),
				CustomRulesOnly:  c.Bool("custom-rules"),
				ShowDiff:         c.Bool("show-diff"),
				Async:            c.Bool("async"),
			}

			return CopyRules(copyRulesInput)
		},
	}
}
