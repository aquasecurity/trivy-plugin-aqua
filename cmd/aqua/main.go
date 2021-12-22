package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"

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
	tags       map[string]string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&severities, "severities", strings.Join(scanner.AllSeverities, ","), "Minimum severity to display misconfigurations for")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "v", false, "Display debug output")
	rootCmd.PersistentFlags().StringToStringVarP(&tags, "tags", "t", nil, "Add arbitrary tags to the scan; --tags key1=val1,key2=val2")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:          "aqua <scanPath>",
	Short:        "Scan a filesystem location for vulnerabilities and config misconfiguration",
	Hidden:       true,
	SilenceUsage: true,
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

		processedResults := processor.ProcessResults(client, results)
		if err != nil {
			return err
		}

		if err := uploader.Upload(client, processedResults, tags); err != nil {
			return err
		}

		return checkPolicyResults(processedResults)
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

func checkPolicyResults(results []*buildsecurity.Result) error {
	uniqCount := 0
	uniq := make(map[string]bool)

	for _, result := range results {
		for _, policyResult := range result.PolicyResults {
			if !policyResult.Failed {
				continue
			}

			if _, ok := uniq[policyResult.GetPolicyID()]; !ok && policyResult.Failed {
				if policyResult.Enforced {
					uniqCount += 1
					log.Logger.Errorf("Enforced policy failure: %s", policyResult.Reason)
				} else {
					log.Logger.Warnf("Unenforced policy failure: %s", policyResult.Reason)
				}
				uniq[policyResult.GetPolicyID()] = true
			}
		}
	}

	if uniqCount == 0 {
		return nil
	}

	return fmt.Errorf("\n%d enforced policy failure(s). See output for specific details.\n\n", uniqCount)
}
