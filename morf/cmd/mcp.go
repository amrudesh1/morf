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
	"fmt"
	"os"

	"morf/mcp"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

// GetMCPCmd returns the `morf mcp` subcommand, which starts a standalone stdio
// MCP (Model Context Protocol) server. It speaks MCP over stdin/stdout so an
// MCP client (e.g. an LLM agent runner) can drive MORF's in-process tools —
// scan_file, list_patterns, verify_secret, explain_finding — with no HTTP
// server, database, or Redis running. All wiring lives in package mcp; this
// command just builds the server and serves it.
func GetMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run MORF as a stdio MCP server (scan/patterns/verify over stdin/stdout)",
		Long: `Start a standalone Model Context Protocol (MCP) server that speaks over
stdin/stdout. It exposes MORF's in-process capabilities as MCP tools so an MCP
client (such as an LLM agent) can use them directly, with no HTTP API,
database, or Redis:

  scan_file(path, format?, verify?)  Scan a local .apk/.ipa; returns a masked
                                     findings summary + SARIF/JSON report.
  list_patterns()                    List the loaded pattern files and counts.
  verify_secret(type, value)         Return a liveness status only (never the
                                     value); respects MORF_ENABLE_VERIFICATION.
  explain_finding(type)              Explain a secret type and its MASVS id.

Secret values are always masked in tool output; raw secrets are never returned
over MCP. The server runs until stdin is closed.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := mcpserver.ServeStdio(mcp.NewServer()); err != nil {
				fmt.Fprintln(os.Stderr, "morf mcp:", err)
				os.Exit(1)
			}
		},
	}
}
