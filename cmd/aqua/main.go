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
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"
)

var (
	skipResultUpload bool
	tags             map[string]string
)

func main() {
	app := cli.NewApp()
	app.Name = "aqua"
	app.Version = "0.0.1"
	app.ArgsUsage = "target"
	app.Usage = "Scan a filesystem location for vulnerabilities and config misconfiguration"
	app.EnableBashCompletion = true

	configCmd := commands.NewConfigCommand()
	configCmd.Action = runScan
	configCmd.Flags = append(configCmd.Flags,
		&cli.StringFlag{
			Name:    "skip-result-upload",
			Usage:   "Add this flag if you want test failed policy locally before sending PR",
			EnvVars: []string{"TRIVY_SKIP_RESULT_UPLOAD"},
		},
		&cli.StringFlag{
			Name:    "vuln-type",
			Value:   strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","),
			Usage:   "comma-separated list of vulnerability types (os,library)",
			EnvVars: []string{"TRIVY_VULN_TYPE"},
			Hidden:  true,
		},
		&cli.StringFlag{
			Name:    "security-checks",
			Value:   types.SecurityCheckConfig,
			Usage:   "comma-separated list of what security issues to detect (vuln,config)",
			EnvVars: []string{"TRIVY_SECURITY_CHECKS"},
			Hidden:  true,
		},
	)

	fsCmd := commands.NewFilesystemCommand()
	fsCmd.Action = runScan
	fsCmd.Flags = append(fsCmd.Flags,
		&cli.StringFlag{
			Name:    "skip-result-upload",
			Usage:   "Add this flag if you want test failed policy locally before sending PR",
			EnvVars: []string{"TRIVY_SKIP_RESULT_UPLOAD"},
		},
	)

	app.Action = runScan
	app.Flags = fsCmd.Flags

	app.Commands = []*cli.Command{
		fsCmd,
		configCmd,
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func runScan(c *cli.Context) error {
	if c.Command.Name == "" {
		if err := c.Set("security-checks", "config"); err != nil {
			return err
		}
		if err := c.Set("vuln-type", "os,library"); err != nil {
			return err
		}
	}

	debug := c.Bool("debug")

	if err := log.InitLogger(debug, false); err != nil {
		return err
	}

	scanPath, _ := os.Getwd()
	if c.Args().Len() > 0 {
		// when scan path provided, use that
		scanPath = c.Args().First()
	}
	log.Logger.Debugf("Using scanPath %s", scanPath)

	client, err := buildClient.Get(scanPath)
	if err != nil {
		return err
	}

	results, err := scanner.Scan(c, scanPath)
	if err != nil {
		return err
	}

	processedResults := processor.ProcessResults(client, results)
	if err != nil {
		return err
	}

	if !skipResultUpload {
		if err := uploader.Upload(client, processedResults, tags); err != nil {
			return err
		}
	}

	return checkPolicyResults(processedResults)
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
