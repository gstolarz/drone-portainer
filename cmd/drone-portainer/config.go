package main

import (
	"github.com/urfave/cli/v2"

	"github.com/gstolarz/drone-portainer/plugin"
)

// settingsFlags has the cli.Flags for the plugin.Settings.
func settingsFlags(settings *plugin.Settings) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "portainer",
			Usage:       "portainer",
			EnvVars:     []string{"PLUGIN_PORTAINER"},
			Destination: &settings.Portainer,
		},
		&cli.BoolFlag{
			Name:        "insecure",
			Usage:       "insecure",
			EnvVars:     []string{"PLUGIN_INSECURE"},
			Destination: &settings.Insecure,
		},
		&cli.StringFlag{
			Name:        "username",
			Usage:       "username",
			EnvVars:     []string{"PLUGIN_USERNAME"},
			Destination: &settings.Username,
		},
		&cli.StringFlag{
			Name:        "password",
			Usage:       "password",
			EnvVars:     []string{"PLUGIN_PASSWORD"},
			Destination: &settings.Password,
		},
		&cli.StringFlag{
			Name:        "endpoint",
			Usage:       "endpoint",
			EnvVars:     []string{"PLUGIN_ENDPOINT"},
			Destination: &settings.Endpoint,
		},
		&cli.StringFlag{
			Name:        "stack",
			Usage:       "stack",
			EnvVars:     []string{"PLUGIN_STACK"},
			Destination: &settings.Stack,
		},
		&cli.StringFlag{
			Name:        "file",
			Usage:       "file",
			EnvVars:     []string{"PLUGIN_FILE"},
			Destination: &settings.File,
		},
		&cli.StringSliceFlag{
			Name:        "environment",
			Usage:       "environment",
			EnvVars:     []string{"PLUGIN_ENVIRONMENT"},
			Destination: &settings.Environment,
		},
		&cli.StringSliceFlag{
			Name:        "networks",
			Usage:       "networks",
			EnvVars:     []string{"PLUGIN_NETWORKS"},
			Destination: &settings.Networks,
		},
		&cli.StringSliceFlag{
			Name:        "configs",
			Usage:       "configs",
			EnvVars:     []string{"PLUGIN_CONFIGS"},
			Destination: &settings.Configs,
		},
	}
}
