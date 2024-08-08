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
*/package cmd

import (
	"fmt"

	"github.com/amrudesh1/morf/apk"
	"github.com/amrudesh1/morf/db"

	log "github.com/sirupsen/logrus"
	cob "github.com/spf13/cobra"
)

var apkPath string
var jsonPath string
var is_db_req bool

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
	is_db_req, _ = cmd.Flags().GetBool("db")

	fmt.Println(is_db_req)

	if is_db_req {
		db.InitDB()
	}

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
	fmt.Println("IS DB REQ", is_db_req)
	// Check if APK path is absolute or relative

	apk.StartCliExtraction(apkPath, db.DB, is_db_req)
}
