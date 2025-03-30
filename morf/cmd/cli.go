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
*/

package cmd

import (
	"morf/apk"
	"morf/db"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// GetCliCmd returns the CLI command for MORF
func GetCliCmd() *cobra.Command {
	var apkPath string
	var jsonPath string
	var useDb bool

	var cliCmd = &cobra.Command{
		Use:   "cli",
		Short: "Run MORF in CLI mode",
		Long:  `Process mobile applications through command line interface`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 && apkPath == "" {
				cmd.Help()
				return
			}

			// Use the first argument as APK path if not provided via flag
			if apkPath == "" && len(args) > 0 {
				apkPath = args[0]
			}

			// Validate APK file extension
			if apkPath[len(apkPath)-4:] != ".apk" {
				log.Error("The file must be an APK file")
				return
			}

			// Initialize database if requested
			if useDb {
				db.InitDB()
			}

			log.Info("Starting APK analysis for:", apkPath)

			// Start the extraction process
			if useDb && db.DatabaseRequired {
				apk.StartCliExtraction(apkPath, db.GormDB, true)
			} else {
				apk.StartCliExtraction(apkPath, nil, false)
			}
		},
	}

	// Add command flags
	cliCmd.Flags().StringVarP(&apkPath, "apk", "a", "", "Path to the APK file")
	cliCmd.Flags().StringVarP(&jsonPath, "json", "j", "", "Path to output JSON file")
	cliCmd.Flags().BoolVarP(&useDb, "use-db", "d", false, "Enable database storage")

	return cliCmd
}
