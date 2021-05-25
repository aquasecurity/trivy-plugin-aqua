# trivy-plugin-aqua
A [Trivy](https://github.com/aquasecurity/trivy) plugin that scans infrastructure as code templates

## Install

```
$ trivy plugin install github.com/aquasecurity/trivy-plugin-aqua
$ trivy aqua -h
Usage: trivy aqua [-h,--help] TYPE NAME [TRIVY OPTION]
 A Trivy plugin that scans infrastructure as code templates.

Options:
  -h, --help    Show usage.

Examples:
  # Scan an IaC file
  trivy plugin run aqua iac --aqua-key <key> --aqua-secret <secret> <target>

```

## Usage
Trivy's options need to be passed after `--`.

```
# Scan an IaC file
trivy plugin run aqua iac --aqua-key <key> --aqua-secret <secret> <target>
```

