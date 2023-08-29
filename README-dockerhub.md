# Code Repository Protection with Aqua Security Trivy Plugin

## Description

The **Aqua Security Trivy Plugin** is a premium offering designed to enhance the security of your code repositories by seamlessly integrating with Trivy ([Trivy](https://github.com/aquasecurity/trivy)), an industry-leading vulnerability scanner. Exclusively available for Aqua Security customers, this plugin provides advanced security features beyond standard vulnerability scanning.

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

## GitHub Action Integration Example

To demonstrate the seamless integration of the Aqua Security Trivy Plugin into your development workflow, consider the following GitHub Actions example:

```yaml
name: Code Repository Security Scan

on:
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
          # To customize which severities to scan for, add the following flag: --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL
          # To enable SAST scanning, add: --sast
          # To enable reachability scanning, add: --reachability
          # To enable npm/dotnet non-lock file scanning, add: --package-json / --dotnet-proj
        env:
          AQUA_KEY: ${{ secrets.AQUA_KEY }}
          AQUA_SECRET: ${{ secrets.AQUA_SECRET }}
          GITHUB_TOKEN: ${{ github.token }}
          TRIVY_RUN_AS_PLUGIN: 'aqua'
          # For proxy configuration add env vars: HTTP_PROXY/HTTPS_PROXY, CA-CRET (path to CA certificate)
```

## Compatibility
The plugin is designed for Docker environments and is compatible with Linux containers. 

## License
This GitHub Action is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). It is exclusively available for Aqua Security customers and is not open source. Please contact Aqua Security for licensing details.