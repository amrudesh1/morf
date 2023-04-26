package cmd

import (
	"morf/apk"
	"morf/db"

	log "github.com/sirupsen/logrus"
	cob "github.com/spf13/cobra"
)

var apkPath string
var jsonPath string

var (
	cliCmd = &cob.Command{
		Use:   "cli",
		Short: "Run MORF as a CLI application",
		Long:  ``,
		Run:   add,
	}
)

func init() {
	includeCliFlags(cliCmd)
}

func includeCliFlags(cmd *cob.Command) {
	// Take a file path as argument
	cmd.Flags().String("apk", "", "Path to the APK file")

	// cmd.Flags().StringVarP(&apk, "apk", "a", "", "Path to the APK file")
	cmd.Flags().StringVarP(&jsonPath, "jsonOut", "j", "", "Path to the JSON output file")
}

func add(cmd *cob.Command, args []string) {
	apkPath, _ = cmd.Flags().GetString("apk")

	db.InitDB()

	switch {
	case apkPath == "":
		cmd.HelpFunc()(cmd, args)
		return
	case apkPath[len(apkPath)-4:] != ".apk":
		{
			log.Error("The file must be an APK file")
			return
		}
	}

	apk.StartCliExtraction(apkPath, db.DB)
}
