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
  export TRIVY_RUN_AS_PLUGIN=aqua
  trivy iac --aqua-key <key> --aqua-secret <secret> <target>
```

## Usage
Trivy's options need to be passed after `--`.
Trivy receives a target directory containing IaC files

Set Aqua plugin as Trivy's current default plugin by exporting an environment variable
```
  export TRIVY_RUN_AS_PLUGIN=aqua
```


### Scan an IaC target
```
  trivy iac --aqua-key <key> --aqua-secret <secret> <target>
```

### Scan an IaC target and tag the scan
```
  trivy iac --aqua-key <key> --aqua-secret <secret> --tags key1:value1 --tags key2:value2 <target>
```

### Scan an IaC target and report only specific severities
```
  trivy iac --aqua-key <key> --aqua-secret <secret> --severities CRITICAL,HIGH <target>
```


