package commands

import (
	"fmt"
	"github.com/urfave/cli/v2"

	. "github.com/jonhadfield/azwaf/policy"
)

func CmdRestore(versionOutput string) *cli.Command {
	return &cli.Command{
		Name:  "restore",
		Usage: "restore waf policies",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "custom-rules", Usage: "restore custom rules only", Aliases: []string{"custom", "c"}},
			&cli.BoolFlag{Name: "managed-rules", Usage: "restore managed rules only", Aliases: []string{"managed", "m"}},
			&cli.StringFlag{Name: "target", Usage: "restore a backup policy's rules (custom and/or managed) over an existing policy", Aliases: []string{"t"}},
			&cli.StringFlag{Name: "resource-group", Usage: "resource group to restore new policies to", Aliases: []string{"r"}},
			&cli.BoolFlag{Name: "dry-run", Usage: "don't apply changes", Aliases: []string{"d"}},
			&cli.BoolFlag{Name: "show-diff", Usage: "show differences between existing and updated policies", Aliases: []string{"s"}},
			&cli.BoolFlag{Name: "force", Usage: "make changes without first prompting"},
			&cli.BoolFlag{Name: "fail-fast", Usage: "exit if any error encountered", Aliases: []string{"f"}},
		},
		Action: func(c *cli.Context) error {
			backupPaths := c.Args().Slice()
			if len(backupPaths) == 0 {
				// nolint:errcheck
				_ = cli.ShowSubcommandHelp(c)

				return fmt.Errorf("%s - backup paths are required", GetFunctionName())
			}

			input := &RestorePoliciesInput{
				BaseCLIInput: BaseCLIInput{
					AppVersion:     versionOutput,
					AutoBackup:     c.Bool("auto-backup"),
					Debug:          c.Bool("debug"),
					ConfigPath:     c.String("config"),
					SubscriptionID: c.String("subscription-id"),
					Quiet:          c.Bool("quiet"),
					DryRun:         c.Bool("dry-run"),
				},
				BackupsPaths:     backupPaths,
				Force:            c.Bool("force"),
				ShowDiff:         c.Bool("show-diff"),
				CustomRulesOnly:  c.Bool("custom-rules"),
				ManagedRulesOnly: c.Bool("managed-rules"),
				TargetPolicy:     c.String("target"),
				ResourceGroup:    c.String("resource-group"),
				FailFast:         c.Bool("fail-fast"),
			}

			return RestorePolicies(input)
		},
	}
}
