/*
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
	Args:          cob.MinimumNArgs(1),
	RunE:          runMORF,
}

func Execute() {
	err := MorfCmd.Execute()
	if err != nil {
		os.Exit(1)
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
	logLevel := log.InfoLevel

	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logLevel)

	if vip.GetBool("server") {
		log.Info("Running MORF as a Server")
	} else if vip.GetBool("cli") {

	}

	return nil
}

func init() {

	vip.SetDefault("port", 8080)
	vip.SetDefault("tempPath", "/temp")
	vip.SetDefault("backup_path", "backup/")

	MorfCmd.AddCommand(cliCmd)
	MorfCmd.AddCommand(serverCmd)

}
