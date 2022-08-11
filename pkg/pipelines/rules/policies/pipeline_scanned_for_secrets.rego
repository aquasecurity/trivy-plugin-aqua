package builtin.pipeline.SECRET_SCANNING

import data.lib.pipeline

__rego_metadata__ := {
	"id": "SECRET_SCANNING",
	"avd_id": "",
	"title": "Ensure scanners are in place to identify and prevent sensitive data in pipeline files",
	"severity": "HIGH",
	"type": "Pipeline Yaml Security Check",
	"description": "Detect and prevent sensitive data, such as confidential ID numbers, passwords, etc. in pipelines",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "pipeline"}],
}

vendorToCommandRegexes = {
	"Trivy": [`trivy ?.* fs ?.* --security-checks .*\b(,?)secret\b(,?)`, `trivy ?.* image ?.* --security-checks .*\b(,?)secret\b(,?)`],
	"DetectSecrets": [`detect-secrets.* scan`],
	"GitAllSecrets": [`docker run.* abhartiya/tools_gitallsecrets`],
	"Whispers": [`whispers`],
	"GitSecrets": [`git secrets --scan`],
	"Spectral": [`spectral.* scan`],
	"ShiftLeft": [`shiftleft code-scan`],
}

vendorToTasks = {
	"Aqua": [{
		"name": "argonsecurity/scanner-action",
		"inputs": {"scanners": ["secrets"]},
	}],
	"Trivy": [{"name": "aquasecurity/trivy-action", "inputs": {"security-checks": [`secret`]}}],
	"Gitleaks": [{"name": "zricethezav/gitleaks-action"}],
	"ShiftLeft": [{"name": "ShiftLeftSecurity/scan-action"}],
}

# Checking if pipeline use argon scanner image with secrets scanner
# Check if the job contains SCANNER env variable
does_use_argon_secret_scanning {
	job := input[_].contents.jobs[_]
	pipeline.does_runner_match(job, "argonsecurity/scanner")
	pipeline.does_contain_environment_variable(job, "SCANNERS", "secrets")
}

# Check if the step runs scan and contains SCANNER env variable
does_use_argon_secret_scanning {
	job := input[_].contents.jobs[_]
	pipeline.does_runner_match(job, "argonsecurity/scanner")
	step := job.steps[_]
	step.type == "shell"
	step.shell.script == "scan"
	pipeline.does_contain_environment_variable(step, "SCANNERS", "secrets")
}

does_use_argon_secret_scanning {
	job := input[_].contents.jobs[_]
	pipeline.does_runner_match(job, "argonsecurity/scanner")
	not job.environment_variables.environment_variables.SCANNERS
	step := job.steps[_]
	step.type == "shell"
	step.shell.script == "scan"
	not step.environment_variables.environment_variables.SCANNERS
}

does_use_command {
	job := input[_].contents.jobs[_]
	regexes := vendorToCommandRegexes[vendor]
	pipeline.does_contains_one_of_commands(job, regexes)
}

does_use_task {
	job := input[_].contents.jobs[_]
	step := job.steps[_]
	step.type == "task"
	pipeline.does_task_match(step.task, vendorToTasks)
}

deny[result] {
	not does_use_argon_secret_scanning
	not does_use_command
	not does_use_task
	result := {
		"msg": "No secret scanning tool is used in pipeline",
		"filename": input[0].path,
		"startline": 1,
	}
}
