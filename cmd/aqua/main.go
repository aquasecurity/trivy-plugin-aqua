package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/export"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/processor"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/uploader"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/flag"
)

var (
	tags map[string]string
)

func main() {
	globalFlags := flag.NewGlobalFlagGroup()

	root := newConfigCommand(globalFlags)
	root.Version = "0.27.1"
	root.Use = "aqua [global flags] command [flags] target"
	globalFlags.AddFlags(root)

	versionCmd := commands.NewVersionCommand(globalFlags)
	versionCmd.Short = "Print the version of the trivy import library"

	root.AddCommand(
		newConfigCommand(globalFlags),
		newFilesystemCommand(globalFlags),
		newImageCommand(globalFlags),
		commands.NewPluginCommand(),
		commands.NewClientCommand(globalFlags),
		commands.NewServerCommand(globalFlags),
		commands.NewRepositoryCommand(globalFlags),
		commands.NewRootfsCommand(globalFlags),
	)

	if err := root.Execute(); err != nil {
		log.Logger.Error(err)
		os.Exit(1)
	}
}

func newConfigCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	cmd := commands.NewConfigCommand(globalFlags)
	initCommand(cmd, globalFlags)
	return cmd
}

func newFilesystemCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	cmd := commands.NewFilesystemCommand(globalFlags)
	initCommand(cmd, globalFlags)
	return cmd
}

func newImageCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	cmd := commands.NewImageCommand(globalFlags)
	initCommand(cmd, globalFlags)
	return cmd
}

func initCommand(cmd *cobra.Command, globalFlags *flag.GlobalFlagGroup) {
	flags := &flag.Flags{
		ScanFlagGroup: &flag.ScanFlagGroup{
			SecurityChecks: &flag.SecurityChecksFlag,
		},
		DBFlagGroup: &flag.DBFlagGroup{
			DBRepository: &flag.DBRepositoryFlag,
		},
		VulnerabilityFlagGroup: &flag.VulnerabilityFlagGroup{
			VulnType: &flag.VulnTypeFlag,
		},
	}

	cmd.ResetFlags() // Do not use the OSS flags
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if err := flags.Bind(cmd); err != nil {
			return xerrors.Errorf("flag bind error: %w", err)
		}
		return nil
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		options, err := flags.ToOptions(cmd.Version, args, globalFlags, os.Stdout)
		if err != nil {
			return xerrors.Errorf("flag error: %w", err)
		}
		return runScan(cmd, args, options)
	}
	flags.AddFlags(cmd)
	addCustomFlags(cmd)
}

func addCustomFlags(cmd *cobra.Command) {
	// Add custom flags for the aqua plugin
	// TODO: refactor
	cmd.Flags().Bool("skip-result-upload", false, "Add this flag if you want test failed policy locally before sending PR")
	_ = viper.BindPFlag("skip-result-upload", cmd.Flags().Lookup("skip-result-upload"))
	_ = viper.BindEnv("skip-result-upload", "TRIVY_SKIP_RESULT_UPLOAD")

	// TODO: add skip-policy-exit-code, triggered-by, pipelines and tags
}

func runScan(cmd *cobra.Command, args []string, options flag.Options) error {
	if cmd.Name() == "aqua" {
		viper.Set("security-checks", "config")
		viper.Set("vuln-type", "os,library")
	}
	if triggeredBy := viper.GetString("triggered-by"); triggeredBy != "" {
		viper.Set("triggered-by", strings.ToUpper(triggeredBy))
	}

	debug := options.Debug

	if err := log.InitLogger(debug, false); err != nil {
		return err
	}

	scanPath, _ := os.Getwd()
	if len(args) > 0 {
		// when scan path provided, use that
		scanPath = args[len(args)-1]
	}
	log.Logger.Debugf("Using scanPath %s", scanPath)

	client, err := buildClient.Get(scanPath, cmd.Name(), options)
	if err != nil {
		return err
	}

	report, pipelines, err := scanner.Scan(cmd.Context(), options, cmd.Name(), scanPath)
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
		err = createIgnoreFile(checkSupIDMap, fileName)
		defer os.Remove(fileName)
		if err != nil {
			return err
		}
	}


	if viper.GetString("triggered-by") == "PR" {
		report.Results, err = processor.PrDiffResults(report.Results)
		if err != nil {
			return err
		}
	}

	processedResults, avdUrlMap := processor.ProcessResults(report.Results, policies, checkSupIDMap)
	if err != nil {
		return err
	}

	if !viper.GetBool("skip-result-upload") {
		if len(viper.GetStringSlice("tags")) > 0 {
			tags = convertToTags(viper.GetStringSlice("tags"))
		}
		if err := uploader.Upload(client, processedResults, tags, avdUrlMap, pipelines); err != nil {
			return err
		}
	}

	if assuranceExportPath := os.Getenv("AQUA_ASSURANCE_EXPORT"); assuranceExportPath != "" {
		if err := export.AssuranceData(assuranceExportPath, report, processedResults); err != nil {
			return err
		}
	}

	return checkPolicyResults(processedResults)
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

func createIgnoreFile(checkSupIDMap map[string]string, fileName string) error {
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

	viper.Set("ignorefile", fileName)
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

	if uniqCount == 0 || viper.GetBool("skip-policy-exit-code") {
		return nil
	}

	return fmt.Errorf("\x1b[31m%d enforced policy control failure(s).\n\n\x1b[0m", len(failures))
}
