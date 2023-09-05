# Code Repository Protection with Aqua Security Trivy Plugin

## Description

The **Aqua Security Trivy Plugin** is a premium offering designed to enhance the security of your code repositories by seamlessly integrating with Trivy ([Trivy](https://github.com/aquasecurity/trivy)), an industry-leading vulnerability scanner ([Trivy docs](https://aquasecurity.github.io/trivy)). Exclusively available for Aqua Security customers, this plugin provides advanced security features beyond standard vulnerability scanning.

## Features

- **Enhanced Security Scans**: Aqua Security customers benefit from advanced features including Better Secret Scanning, SAST (Static application security testing), and Reachability Checks.

- **Better Secret Scanning**: Detect sensitive information such as API keys and passwords within your codebase and configuration files to prevent potential leaks.

- **SAST Scanning**: Analyze your source code for security vulnerabilities, including code patterns that could lead to potential exploits.

- **Reachability Check**: Ensure your code interacts only with approved and trusted endpoints, reducing potential attack vectors.

- **Customizable Security Policies**: Tailor security policies to your organization's needs, including severity thresholds and compliance requirements. Please contact Aqua Security for policies details.

- **Detailed Reporting**: Receive comprehensive security reports, complete with actionable remediation recommendations.

- **CI/CD Pipeline Integration**: Seamlessly incorporate the GitHub Action into your CI/CD pipelines to ensure stringent security checks throughout your software development lifecycle.

## Get Started
To begin leveraging the Aqua Security Trivy Integration GitHub Action to protect your code repositories, reach out to our sales or support team to learn more about the benefits and access.


## Environment Variables

### Required

The only explicitly required environment variables are

| Variable    | Purpose                                                       |
|:------------|:--------------------------------------------------------------|
| AQUA_KEY    | Generated through CSPM UI                                     |
| AQUA_SECRET | Generated through CSPM UI                                     |


### Optional

| Variable    | Purpose                                                       |
|:------------|:--------------------------------------------------------------|
| CSPM_URL    | URL to generate Aqua Platform token (default: us-east-1 CSPM) |
| AQUA_URL    | Aqua platform URL (default: us-east-1 Aqua platform)          |



Trivy will attempt to resolve the following details from the available environment variables;

- repository name
- branch name
- commit id
- committing user
- build system

There are some env vars for overriding this data;

| Variable             | Purpose                                                                                |
| :------------------- | :------------------------------------------------------------------------------------- |
| OVERRIDE_REPOSITORY  | Use this environment variable to explicitly specify the repository used by Trivy       |
| FALLBACK_REPOSITORY  | Use this environment variable as a backup if no other repository env vars can be found |
| OVERRIDE_BRANCH      | Use this environment variable to explicitly specify the branch used by Trivy           |
| FALLBACK_BRANCH      | Use this environment variable as a backup if no other branch env vars can be found     |
| OVERRIDE_BUILDSYSTEM | Use this environment variable to explicitly specify the build system                   |
| OVERRIDE_SCMID       | Use this environment variable to explicitly specify the scm id                         |
| IGNORE_PANIC         | Use this environment variable to return exit code 0 on cli panic                       |
| OVERRIDE_REPOSITORY_URL  | Use this environment variable to explicitly specify the repository link used by Trivy (For result's web link)       |
| OVERRIDE_REPOSITORY_SOURCE  | Use this environment variable to explicitly specify the repository source used by Trivy       |


## Command Line Arguments

| Argument         | Purpose                                    | Example Usage                                 |
| ---------------- | ------------------------------------------ | --------------------------------------------- |
| `--debug`        | Get more detailed output as Trivy runs.    |                                               |
| `--severities`   | The Severities that you are interested in. | `--severities CRITICAL,HIGH,UNKNOWN`          |
| `--pipelines`    | Scan repository pipeline files.            | `--pipelines` / `PIPELINES=1 trivy ...`       |
| `--sast`    | To enable SAST scanning.            | `--sast` `       |
| `--reachability`    | To enable reachability scanning.            | `--reachability` `       |
| `--package-json` | Scan package.json files without lock files | `--package-json` / `PACKAGE_JSON=1 trivy ...` |
| `--dotnet-proj`  | Scan dotnet proj files without lock files  | `--dotnet-proj` / `DOTNET_PROJ=1 trivy ...`   |





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
          TRIVY_RUN_AS_PLUGIN: 'aqua'
          # For proxy configuration add env vars: HTTP_PROXY/HTTPS_PROXY, CA-CRET (path to CA certificate)
```

### Usage for running manually using docker command

```bash
docker run -it aquasec/aqua-scanner trivy fs --scanners config,vuln,secret .
```

## Usage with Podman


```bash
podman pull aquasec/aqua-scanner

podman run -it --rm --security-opt seccomp=unconfined aquasec/aqua-scanner trivy fs --scanners config,vuln,secret .

```


## Compatibility
The plugin is designed for Docker environments and is compatible with Linux containers. 

## License
This GitHub repository is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). It is exclusively available for Aqua Security customers and is not open source. Please contact Aqua Security for licensing details.
