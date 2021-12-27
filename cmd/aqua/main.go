package main

import (
	"fmt"
	"os"
	"sort"

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

	var warns []string
	var failures []string

	for _, result := range results {
		for _, policyResult := range result.PolicyResults {
			if !policyResult.Failed {
				continue
			}

			if policyResult.Enforced {
				for _, reason := range strings.Split(policyResult.Reason, "\n") {
					if reason == "" {
						continue
					}
					uniqCount += 1
					failures = append(failures, reason)
				}
			} else {
				for _, reason := range strings.Split(policyResult.Reason, "\n") {
					if reason == "" {
						continue
					}
					warns = append(warns, reason)
				}
			}
		}
	}

	if len(warns) > 0 {
		sort.Strings(warns)
		_, _ = fmt.Fprintf(os.Stderr, "\n\x1b[33mAqua Assurance Policy warnings were triggered by the following checks failing:\n\n\x1b[0m")
		for _, warn := range warns {
			_, _ = fmt.Fprintf(os.Stderr, "\t- %s\n", warn)
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if len(failures) > 0 {
		sort.Strings(failures)
		_, _ = fmt.Fprintf(os.Stderr, "\n\x1b[31mAqua Assurance Policy build failed with the following checks failing:\n\n\x1b[0m")
		for _, failure := range failures {
			_, _ = fmt.Fprintf(os.Stderr, "\t- %s\n", failure)
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if uniqCount == 0 {
		return nil
	}

	return fmt.Errorf("\x1b[31m%d enforced policy control failure(s).\n\n\x1b[0m", len(failures))
}
