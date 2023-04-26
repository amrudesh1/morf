package cmd

import (
	"morf/db"
	route "morf/router"

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
	route.InitRouters(router)

	// r.SetTrustedProxies(nil)
	r.Run(":" + vip.GetString("port"))
}
