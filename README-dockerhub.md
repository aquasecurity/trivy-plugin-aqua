# Code Repository Protection with Aqua Security Trivy Plugin

## Description

The **Aqua Security Trivy Plugin** is a premium offering designed to enhance the security of your code repositories by seamlessly integrating with Trivy ([Trivy](https://github.com/aquasecurity/trivy)), an industry-leading vulnerability scanner ([Trivy docs](https://aquasecurity.github.io/trivy)). Exclusively available for Aqua Security customers, this plugin provides advanced security features beyond standard vulnerability scanning.

## Features

- **Enhanced Security Scans**: Aqua Security customers benefit from advanced features including Enhenced Secret Scanning engine, SAST (Static application security testing), Reachability Checks, and more.

- **Better Secret Scanning**: Detect sensitive information such as API keys and passwords within your codebase and configuration files to prevent potential leaks.

- **SAST Scanning**: Analyze your source code for security vulnerabilities, including code patterns that could lead to potential exploits.

- **Reachability Check**: This analysis provides more granular information to understand whether an existing vulnerability is reachable to the packages in your code repository. If a vulnerability is reachable, you may prioritize fixing it.

- **Customizable Security Policies**: Tailor security policies to your organization's needs, including severity thresholds and compliance requirements. For more information, please see the Aqua official documentation.

- **Detailed Reporting**: Receive comprehensive security reports, complete with actionable remediation recommendations.

- **CI/CD Pipeline Integration**: Seamlessly incorporate into your CI/CD pipelines to ensure stringent security checks throughout your software development lifecycle.

## Get Started

To begin leveraging the Aqua Security Trivy Integration to protect your code repositories, reach out to our sales or support team to learn more about the benefits and access.

## Environment Variables

### Required

The only explicitly required environment variables are

| Variable    | Purpose                   |
| :---------- | :------------------------ |
| AQUA_KEY    | Generated through CSPM UI |
| AQUA_SECRET | Generated through CSPM UI |

### Optional

| Variable | Purpose                                              |
| :------- | :--------------------------------------------------- |
| CSPM_URL | Aqua CSPM URL (default: us-east-1 CSPM)              |
| AQUA_URL | Aqua platform URL (default: us-east-1 Aqua platform) |

Trivy will attempt to resolve the following details from the available environment variables;

- repository name
- branch name
- commit id
- committing user
- build system

There are some environments variables for overriding default values and behaviors;

| Variable                   | Purpose                                                                                                                                                              |
| :------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OVERRIDE_REPOSITORY        | Use this environment variable to explicitly specify the repository name used by Trivy                                                                                |
| FALLBACK_REPOSITORY        | Use this environment variable as a backup if no other repository env vars can be found                                                                               |
| OVERRIDE_BRANCH            | Use this environment variable to explicitly specify the branch used by Trivy                                                                                         |
| FALLBACK_BRANCH            | Use this environment variable as a backup if no other branch env vars can be found                                                                                   |
| OVERRIDE_BUILDSYSTEM       | Use this environment variable to explicitly specify the build system                                                                                                 |
| IGNORE_PANIC               | Use this environment variable to return exit code 0 on cli panic error                                                                                               |
| OVERRIDE_REPOSITORY_URL    | Use this environment variable to explicitly specify the repository link used by Trivy (For result's web link)                                                        |
| OVERRIDE_REPOSITORY_SOURCE | Use this environment variable to explicitly specify the repository source used by Trivy                                                                              |
| HTTP_PROXY/HTTPS_PROXY     | Use these environment variable for proxy configuration                                                                                                               |
| XDG_DATA_HOME              | use this environment variable to designate the base directory for storing user-specific data                                                                         |
| XDG_CACHE_HOME             | use this environment variable for setting the cache directory                                                                                                        |
| SAST_LOGS                  | use this environment variable with true value for writing sast logs to a file (The file name is: ${REPOSITORY_NAME}-sast-logs.txt under the SAST_LOGS_DIR directory) |
| SAST_LOGS_DIR              | use this environment variable to explicitly specify the location where the log file should be written (Default is /tmp/.trivy/plugins/aqua)                          |
| TRIVY_QUIET                | Disable trivy output report in log                                                                                                                                   |
| AQUA_ASSURANCE_EXPORT      | The path to export policies results (JSON)                                                                                                                           |
| OVERRIDE_AUTHOR            | Use this environment variable to override the author of the scan (commit pusher by default)                   |
| OVERRIDE_RUN_ID            | Use this environment variable to override the run id (default to SCM run build number)                        |
| OVERRIDE_BUILD_ID          | Use this environment variable to override the job/build id (default to SCM build id)                          |
## Command Line Arguments

| Argument                  | Environment variable        | Purpose                                                      | Example Usage                                                                |
| ------------------------- | --------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `--debug`                 | DEBUG                       | Get more detailed output as Trivy runs.                      | `--debug` / DEBUG=true                                                       |
| `--severities`            | TRIVY_SEVERITY              | The Severities that you are interested in.                   | `--severities CRITICAL,HIGH,UNKNOWN` / TRIVY_SEVERITY= CRITICAL,HIGH,UNKNOWN |
| `--skip-pipelines`        | SKIP_PIPELINES              | Skip scan repository pipeline files.                         | `--skip-pipelines` / SKIP_PIPELINES=true                                     |
| `--sast`                  | SAST                        | To enable SAST scanning.                                     | `--sast` / SAST=true                                                         |
| `--reachability`          | REACHABILITY                | To enable reachability scanning.                             | `--reachability` / REACHABILITY=true                                         |
| `--package-json`          | PACKAGE_JSON                | Scan package.json files without lock files                   | `--package-json` / `PACKAGE_JSON=true`                                       |
| `--dotnet-proj`           | DOTNET_PROJ                 | Scan dotnet proj files without lock files                    | `--dotnet-proj` / `DOTNET_PROJ=true`                                         |
| `--skip-policies`         | TRIVY_SKIP_POLICIES         | Skip policies checks                                         | `--skip-policies` / `TRIVY_SKIP_POLICIES=true`                               |
| `--skip-result-upload`    | TRIVY_SKIP_RESULT_UPLOAD    | Disable uploading scan results to aqua platform              | `--skip-result-upload` / `TRIVY_SKIP_RESULT_UPLOAD=true`                     |
| `--skip-policy-exit-code` | TRIVY_SKIP_POLICY_EXIT_CODE | Prevent non-zero exit code if an assurance policy has failed | `--skip-policy-exit-code` / `TRIVY_SKIP_POLICY_EXIT_CODE=true`               |

## GitHub Action Integration Example

To demonstrate the seamless integration of the Aqua Security Trivy Plugin into your development workflow, which can run triggered by push (full scan) or triggered by creating a pull request (scan the Git diff's), consider the following GitHub Actions example:

```yaml
name: Code Repository Security Scan

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  security_scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Run Aqua scanner
        uses: docker://aquasec/aqua-scanner
        with:
          args: trivy fs --scanners config,vuln,secret .
        env:
          AQUA_KEY: ${{ secrets.AQUA_KEY }}
          AQUA_SECRET: ${{ secrets.AQUA_SECRET }}
          GITHUB_TOKEN: ${{ github.token }}
          TRIVY_RUN_AS_PLUGIN: "aqua"
          # Use here any other environment variable
```

### Usage for running manually using docker command

```bash
AQUA_KEY=${AQUA_KEY} AQUA_SECRET=${AQUA_SECRET} TRIVY_RUN_AS_PLUGIN=aqua docker run -it -e AQUA_KEY -e AQUA_SECRET -e TRIVY_RUN_AS_PLUGIN -e INPUT_WORKING_DIRECTORY=/scanning -v "${YOUR_WORKSPACE}":"/scanning" aquasec/aqua-scanner trivy fs --scanners config,vuln,secret .
```

## Usage with Podman

```bash
podman run --rm \
                -e AQUA_KEY=${AQUA_KEY} \
                -e AQUA_SECRET=${AQUA_SECRET} \
                -e TRIVY_RUN_AS_PLUGIN='aqua' \
                -e SAST='true' \
                -e INPUT_WORKING_DIRECTORY='/scanning' \
                -v ${WORKSPACE}:/scanning \
                docker.io/aquasec/aqua-scanner \
                git config --global --add safe.directory /scanning && trivy fs --scanners='config,vuln,secret' .

```

When working within CI environment, it's important to include the Source Code Management (SCM) tokens for pull requests. You can find additional guidance and details on this matter within our platform for your reference about each SCM.

# aqua-scanner limited Tag (Beta)

We now provide a dedicated limited permission tag, for running the aqua-scanner on a non-root user.

Tag name: `latest-limited`
Support for: linux/amd64, linux/arm64

## Running limited tag on Azure DevOps pipeline

To use the limited tag effectively on Azure DevOps Pipelines, follow the steps below ([Azure documentation](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/container-phases?view=azure-devops&tabs=yaml#linux-based-containers)), consider the following Azure DevOps pipeline example (with the -u 0 option):

```yaml
trigger:
  - main

container:
  image: aquasec/aqua-scanner:latest-limited
  options: -u 0
  env:
    AQUA_KEY: $(AQUA_KEY)
    AQUA_SECRET: $(AQUA_SECRET)
    AZURE_TOKEN: $(AZURE_TOKEN)
    TRIVY_RUN_AS_PLUGIN: aqua
steps:
  - checkout: self
    fetchDepth: 0
  - script: |
      trivy fs --scanners config,vuln,secret .
    displayName: Aqua scanner
```

## Compatibility

The plugin is designed for Docker environments and is compatible with Linux containers.

## License

This GitHub repository is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). It is exclusively available for Aqua Security customers and is not open source. Please contact Aqua Security for licensing details.