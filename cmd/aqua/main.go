package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/export"

	"github.com/aquasecurity/trivy/pkg/types"

	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/processor"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/uploader"
	"github.com/aquasecurity/trivy/pkg/commands"
)

var (
	tags map[string]string
)

func main() {
	app := cli.NewApp()
	app.Name = "aqua"
	app.Version = "0.27.1"
	app.ArgsUsage = "target"
	app.Usage = "A simple and comprehensive vulnerability scanner for containers"
	app.EnableBashCompletion = true

	configCmd := commands.NewConfigCommand()
	configCmd.Action = runScan
	configCmd.Flags = append(configCmd.Flags,
		&cli.BoolFlag{
			Name:    "skip-result-upload",
			Usage:   "Add this flag if you want test failed policy locally before sending PR",
			EnvVars: []string{"TRIVY_SKIP_RESULT_UPLOAD"},
		},
		&cli.BoolFlag{
			Name:    "skip-policy-exit-code",
			Usage:   "Add this flag if you want skip policies exit code",
			EnvVars: []string{"TRIVY_SKIP_POLICY_EXIT_CODE"},
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
			Usage:   "comma-separated list of what security issues to detect (vuln,config,secret)",
			EnvVars: []string{"TRIVY_SECURITY_CHECKS"},
			Hidden:  true,
		},
		&cli.StringFlag{
			Name:    "triggered-by",
			Usage:   "Add this flag to determine where the scan is coming from (push, pr, offline)",
			EnvVars: []string{"TRIGGERED_BY"},
		},
	)

	fsCmd := commands.NewFilesystemCommand()
	fsCmd.Action = runScan
	fsCmd.Flags = append(fsCmd.Flags,
		&cli.BoolFlag{
			Name:    "skip-result-upload",
			Usage:   "Add this flag if you want test failed policy locally before sending PR",
			EnvVars: []string{"TRIVY_SKIP_RESULT_UPLOAD"},
		},
		&cli.BoolFlag{
			Name:    "skip-policy-exit-code",
			Usage:   "Add this flag if you want skip policies exit code",
			EnvVars: []string{"TRIVY_SKIP_POLICY_EXIT_CODE"},
		},
		&cli.BoolFlag{
			Name:    "debug",
			Usage:   "Add this flag if you want run in debug mode",
			EnvVars: []string{"DEBUG"},
		},
		&cli.StringFlag{
			Name:    "triggered-by",
			Usage:   "Add this flag to determine where the scan is coming from (push, pr, offline)",
			EnvVars: []string{"TRIGGERED_BY"},
		},
		&cli.StringSliceFlag{
			Name:  "tags",
			Usage: "Add this flag for key:val pairs as scan metadata",
		},
	)

	imageCmd := commands.NewImageCommand()
	imageCmd.Action = runScan

	app.Action = runScan
	app.Flags = fsCmd.Flags

	app.Flags = append(app.Flags,
		&cli.BoolFlag{
			Name:    "quiet",
			Usage:   "suppress progress bar and log output (default: false)",
			EnvVars: []string{"TRIVY_QUIET"},
		})

	versionCmd := commands.NewVersionCommand()
	versionCmd.Usage = "print the version of the trivy import library"

	app.Commands = []*cli.Command{
		fsCmd,
		configCmd,
		imageCmd,
		commands.NewPluginCommand(),
		commands.NewClientCommand(),
		commands.NewRepositoryCommand(),
		commands.NewRootfsCommand(),
		commands.NewServerCommand(),
		versionCmd,
	}
	if err := app.Run(os.Args); err != nil {
		log.Logger.Error(err)
		os.Exit(1)
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
	if c.String("triggered-by") != "" {
		if err := c.Set("triggered-by", strings.ToUpper(c.String("triggered-by"))); err != nil {
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

	client, err := buildClient.Get(scanPath, c)
	if err != nil {
		return err
	}

	downloadedPolicies, err := client.GetPoliciesForRepository()
	if err != nil {
		log.Logger.Errorf("Could not download the repository policies. %#v", err)
		return err
	}
	policies, checkSupIDMap := processor.DistinguishPolicies(downloadedPolicies)
	if len(checkSupIDMap) > 0 {
		fileName := fmt.Sprintf("ignoreIds_%s", time.Now().Format("20060102150405"))
		err = createIgnoreFile(c, checkSupIDMap, fileName)
		defer os.Remove(fileName)
		if err != nil {
			return err
		}
	}
	report, err := scanner.Scan(c, scanPath)
	if err != nil {
		return err
	}

	if c.String("triggered-by") == "PR" {
		report.Results, err = processor.PrDiffResults(report.Results)
		if err != nil {
			return err
		}
	}

	processedResults, avdUrlMap := processor.ProcessResults(report.Results, policies, checkSupIDMap)
	if err != nil {
		return err
	}

	if !c.Bool("skip-result-upload") {
		if c.String("tags") != "" {
			tags = convertToTags(c.StringSlice("tags"))
		}
		if err := uploader.Upload(client, processedResults, tags, avdUrlMap); err != nil {
			return err
		}
	}

	if assuranceExportPath := os.Getenv("AQUA_ASSURANCE_EXPORT"); assuranceExportPath != "" {
		if err := export.AssuranceData(assuranceExportPath, report, processedResults); err != nil {
			return err
		}
	}

	return checkPolicyResults(c, processedResults)
}

func convertToTags(t []string) (tags map[string]string) {
	tags = make(map[string]string)
	for _, v := range t {
		if strings.Contains(v, ":") {
			tag := strings.Split(v, ":")
			if tag[0] != "" && tag[1] != "" {
				tags[tag[0]] = tag[1]
			}
		}
	}
	return tags
}

func createIgnoreFile(c *cli.Context, checkSupIDMap map[string]string, fileName string) error {
	log.Logger.Debugf("%d IDs are suppressed", len(checkSupIDMap))
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	for avdId := range checkSupIDMap {
		_, err = writer.WriteString(avdId + "\n")
		if err != nil {
			return err
		}
	}
	err = writer.Flush()
	if err != nil {
		return err
	}
	err = file.Close()
	if err != nil {
		return err
	}

	if err := c.Set("ignorefile", fileName); err != nil {
		return err
	}
	return nil
}

func checkPolicyResults(c *cli.Context, results []*buildsecurity.Result) error {
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
		_, _ = fmt.Fprintf(os.Stderr, "\n\x1b[33mAqua Assurance Policy warnings were"+
			" triggered by the following checks failing:\n\n\x1b[0m")
		for _, warn := range warns {
			_, _ = fmt.Fprintf(os.Stderr, "\t- %s\n", warn)
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if len(failures) > 0 {
		sort.Strings(failures)
		_, _ = fmt.Fprintf(os.Stderr, "\n\x1b[31mAqua Assurance Policy build "+
			"failed with the following checks failing:\n\n\x1b[0m")
		for _, failure := range failures {
			_, _ = fmt.Fprintf(os.Stderr, "\t- %s\n", failure)
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if uniqCount == 0 || c.Bool("skip-policy-exit-code") {
		return nil
	}

	return fmt.Errorf("\x1b[31m%d enforced policy control failure(s).\n\n\x1b[0m", len(failures))
}
