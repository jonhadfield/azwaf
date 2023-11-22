package commands

import (
	. "github.com/jonhadfield/azwaf/policy"
	"github.com/urfave/cli/v2"
)

func CmdBackup(versionOutput string) *cli.Command {
	return &cli.Command{
		Name:  "backup",
		Usage: "backup waf policies to disk and azure storage",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "path", Usage: "where to write backups", Aliases: []string{"p"}, Required: false},
			&cli.StringFlag{Name: "storage-account-id", Usage: "resource id of storage account to backup to", Aliases: []string{"s"}, Required: false},
			&cli.StringFlag{Name: "container-url", Usage: "container url to backup to, ex: https://mystorageacc.blob.core.windows.net/mycontainer", Aliases: []string{"c"}, Required: false},
			&cli.BoolFlag{Name: "fail-fast", Usage: "exit if any error encountered", Aliases: []string{"f"}, Required: false},
		},
		Action: func(c *cli.Context) error {
			input := c.Args().Slice()

			config := BackupPoliciesInput{
				BaseCLIInput: BaseCLIInput{
					AppVersion:     versionOutput,
					AutoBackup:     c.Bool("auto-backup"),
					Debug:          c.Bool("debug"),
					ConfigPath:     c.String("config"),
					SubscriptionID: c.String("subscription-id"),
					Quiet:          c.Bool("quiet"),
					DryRun:         c.Bool("dry-run"),
				},
				RIDs:                     input,
				Path:                     c.String("path"),
				StorageAccountResourceID: c.String("storage-account-id"),
				ContainerURL:             c.String("container-url"),
				FailFast:                 c.Bool("fail-fast"),
			}

			return BackupPolicies(&config)
		},
	}
}
