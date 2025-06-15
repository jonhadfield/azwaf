package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/jonhadfield/azwaf/cmd/commands"

	nested "github.com/antonfisher/nested-logrus-formatter"

	"github.com/sirupsen/logrus"
)

var version, versionOutput, tag, sha, buildDate string

const (
	appName         = "azwaf"
	autoBackup      = true
	defaultLogLevel = "info"
	configFile      = "config.yaml"
)

func init() {
	lvl, ok := os.LookupEnv("AZWAF_LOG")
	// LOG_LEVEL not set, default to info
	if !ok {
		lvl = defaultLogLevel
	}

	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logrus.InfoLevel
	}

	logrus.SetFormatter(&nested.Formatter{
		HideKeys:    true,
		FieldsOrder: []string{"component", "category"},
	})

	logrus.SetLevel(ll)
}

func main() {
	if tag != "" && buildDate != "" {
		versionOutput = fmt.Sprintf("[%s-%s] %s UTC", tag, sha, buildDate)
	} else {
		versionOutput = version
	}

	// get home dir to use as part of config path
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("\nerror: %s\n", err)
	}

	app := cli.NewApp()
	app.EnableBashCompletion = true

	app.Name = appName
	app.Version = versionOutput
	app.Compiled = time.Now()
	app.Authors = []*cli.Author{
		{
			Name:  "Jon Hadfield",
			Email: "jon@lessknown.co.uk",
		},
	}
	app.HelpName = ""
	app.Description = "azwaf is a client for managing Azure Front Door WAF policies.\n\nwaf policy ids can be substituted for shorter \"hashes\" that can\nbe found by running: 'azwaf list policies'"
	app.Usage = "azwaf [global options] command [command options] [arguments...]"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     commands.FlagSubscriptionID,
			Usage:    "specify the suscription id containing the policies",
			EnvVars:  []string{"AZURE_SUBSCRIPTION_ID"},
			Aliases:  []string{"s", "subscription"},
			Required: false,
		},
		&cli.StringFlag{
			Name: commands.FlagConfig, Usage: "path to configuration file",
			Value: filepath.Join(home, ".config", appName, configFile),
		},
		&cli.BoolFlag{Name: "quiet", Usage: "suppress output"},
		&cli.BoolFlag{Name: commands.FlagAutoBackup, Usage: "backup policy before applying any changes", Value: autoBackup},
	}
	app.Commands = []*cli.Command{
		commands.CmdAdd(versionOutput),
		commands.CmdBackup(versionOutput),
		commands.CmdCopy(versionOutput),
		commands.CmdDelete(versionOutput),
		commands.CmdGet(),
		commands.CmdList(),
		commands.CmdRestore(versionOutput),
		commands.CmdShow(),
	}

	if err = app.Run(os.Args); err != nil {
		// it's a stdlib error
		fmt.Printf("\nerror: %s\n", err)

		return
	}
}
