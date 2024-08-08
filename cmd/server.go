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
	"net/http"
	"time"

	"github.com/amrudesh1/morf/db"
	route "github.com/amrudesh1/morf/router"

	gin "github.com/gin-gonic/gin"
	cob "github.com/spf13/cobra"
	vip "github.com/spf13/viper"
)

var port int = 0
var (
	serverCmd = &cob.Command{Use: "server", Short: "Starts MORF as a Service", Long: ``, Run: runServer}
)

func init() {
	includeServerFlags(serverCmd)
}

func includeServerFlags(cmd *cob.Command) {
	cmd.Flags().IntVarP(&port, "port", "p", 8080, "The default port is 8080")
}

func runServer(cmd *cob.Command, args []string) {
	switch {
	case port != 0:
		vip.SetDefault("port", port)
	}

	db.InitDB()
	r := gin.Default()
	r.MaxMultipartMemory = 8 << 20 // 8 Mi

	router := r.Group("/api")

	srv := &http.Server{
		Addr:         ":" + vip.GetString("port"),
		Handler:      r,
		ReadTimeout:  5 * 60 * time.Second,
		WriteTimeout: 10 * 60 * time.Second,
	}
	route.InitRouters(router)

	srv.ListenAndServe()
}
