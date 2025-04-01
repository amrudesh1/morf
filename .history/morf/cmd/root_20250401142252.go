/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/ /*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	cob "github.com/spf13/cobra"
	vip "github.com/spf13/viper"
)

var MorfCmd = &cob.Command{
	Use:           "MORF",
	Short:         "Mobile Reconnaissance Framework",
	SilenceErrors: true,
	SilenceUsage:  true,
	PreRunE:       preFlight,
	Args:          cob.MinimumNArgs(2),
	RunE:          runMORF,
}

func Execute() {

	err := MorfCmd.Execute()
	if err != nil {
		MorfCmd.HelpFunc()(MorfCmd, os.Args)
	}
}

func preFlight(cmd *cob.Command, args []string) error {

	// Check if we are running as a server or a cli application
	if !vip.GetBool("server") && !vip.GetBool("cli") {
		cmd.HelpFunc()(cmd, args)
		return nil
	}
	return nil
}

func runMORF(cmd *cob.Command, args []string) error {
	logLevel := log.DebugLevel

	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logLevel)

	if vip.GetBool("server") {
		log.Info("Running MORF as a Server")
	} else if vip.GetBool("cli") {
		log.Info("Running MORF as a CLI")
	}

	return nil
}

func init() {
	vip.SetDefault("port", 8080)
	vip.SetDefault("backup_path", "backup/")
	vip.SetDefault("db_name", "Secrets")

	MorfCmd.AddCommand(GetCliCmd())
	MorfCmd.AddCommand(GetServerCmd())
}
