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

| Argument | Purpose | Example Usage |
|----------|---------|---------------|
|`--debug`| Get more detailed output as Trivy runs.||
|`--severities`|The Severities that you are interested in. | `--severities CRITICAL,HIGH,UKNOWN` |
|`--tags`|Arbitrary tags to be stored with the scan. | `--tags 'BUILD_HOST=$HOSTNAME,foo=bar'` |

## Environment Variables

### Required

The only explicitly required environment variables are

| Variable    | Purpose                   |
| :---------- | :-------------------------|
| AQUA_KEY    | Generated through CSPM UI |
| AQUA_SECRET | Generated through CSPM UI |

### Optional

Trivy will attempt to resolve the following details from the available environment variables;

- repository name
- branch name
- commit id
- committing user
- build system

There are some special case env vars;

| Variable             | Purpose                                                                                 |
| :------------------- |:--------------------------------------------------------------------------------------- |
| OVERRIDE_REPOSITORY  | Use this environment variable to explicitly specify the repository used by Trivy        |
| FALLBACK_REPOSITORY  | Use this environment variable as a backup if no other repository env vars can be found  |
| OVERRIDE_BRANCH      | Use this environment variable to explicitly specify the branch used by Trivy            |
| FALLBACK_BRANCH      | Use this environment variable as a backup if no other branch env vars can be found      |
| OVERRIDE_BUILDSYSTEM | Use this environment variable to explicitly specify the build system                    |

