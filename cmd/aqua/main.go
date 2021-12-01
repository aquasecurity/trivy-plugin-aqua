package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/processor"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/uploader"
	"github.com/spf13/cobra"
)

var (
	severities string
	debug      bool
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&severities, "severities", "", strings.Join(scanner.AllSeverities, ","), "Minimum severity to display misconfigurations for")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "Display debug output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:    "aqua <scanPath>",
	Short:  "Scan a filesystem location for vulnerabilities and config misconfiguration",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := log.InitLogger(debug, false); err != nil {
			return err
		}

		if err := verifySeverities(); err != nil {
			return err
		}

		scanPath, _ := os.Getwd()
		if len(args) > 0 {
			// when scan path provided, use that
			scanPath = args[0]
		}
		log.Logger.Debugf("Using scanPath %s", scanPath)

		client, err := buildClient.Get(scanPath)
		if err != nil {
			return err
		}

		results, err := scanner.Scan(scanPath, severities, debug)
		if err != nil {
			return err
		}

		iacResults, breakBuild := processor.ProcessResults(client, results)
		if err != nil {
			return err
		}

		if err := uploader.Upload(client, iacResults); err != nil {
			return err
		}

		if breakBuild {
			return fmt.Errorf("build failed to satisfy all policies")
		}

		return nil
	},
	Args: cobra.ExactArgs(1),
}

func verifySeverities() error {

	if severities != "" {
		severities = strings.ToUpper(severities)
		sevList := strings.Split(severities, ",")
		for _, sev := range sevList {
			if !scanner.AllSeverities.Any(sev) {
				return fmt.Errorf("could not resolve the provided severity: %s\nOptions are: [%s]\n", sev, strings.Join(scanner.AllSeverities, ", "))
			}
		}
	}
	return nil
}
