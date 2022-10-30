# trivy-plugin-aqua

Trivy plugin for integration with Aqua Security SaaS platform

## Usage

Trivy's options need to be passed after `--`. Trivy receives a target directory containing IaC files

Set Aqua plugin as Trivy's current default plugin by exporting an environment variable

```
  export TRIVY_RUN_AS_PLUGIN=aqua
```

### Scan an IaC target

```
  trivy  <target>
```

### Scan an IaC target and tag the scan

```
  trivy  <target>
```

### Scan an IaC target and report only specific severities

```
  trivy --severities CRITICAL,HIGH <target>
```

## Command Line Arguments

| Argument         | Purpose                                    | Example Usage                                 |
| ---------------- | ------------------------------------------ | --------------------------------------------- |
| `--debug`        | Get more detailed output as Trivy runs.    |                                               |
| `--severities`   | The Severities that you are interested in. | `--severities CRITICAL,HIGH,UNKNOWN`          |
| `--tags`         | Arbitrary tags to be stored with the scan. | `--tags 'BUILD_HOST=$HOSTNAME,foo=bar'`       |
| `--pipelines`    | Scan repository pipeline files.            | `--pipelines` / `PIPELINES=1 trivy ...`       |
| `--package-json` | Scan package.json files without lock files | `--package-json` / `PACKAGE_JSON=1 trivy ...` |

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

There are some special case env vars;

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

# Scanners

Certain scanners have additional behaviors

### Pipelines

The pipelines scanner uses [Pipeline Parser](https://github.com/argonsecurity/pipeline-parser) to parse the pipelines, and therefore, supports only the platforms that are supported by the package.

The results of the scanner are:

- parsed version of the pipeline files
- pipeline misconfigurations

# Deployment of a new version

To deploy a new version, create a new tag from master

```bash
make update-plugin
```
