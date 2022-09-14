package builtin.pipeline.VULN_SCANNING

import data.lib.pipeline

__rego_metadata__ := {
	"id": "PIPELINE-0021",
	"avd_id": "AVD-PIPELINE-0021",
	"title": "Ensure pipelines are automatically scanned for vulnerabilities",
	"severity": "HIGH",
	"type": "Pipeline Yaml Security Check",
	"description": "Scan pipelines for vulnerabilities. It is recommended to do that automatically.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "pipeline"}],
}

vendorToCommandRegexes = {
	"Trivy": [`(\.\/)?trivy ?.* (fs|image)\b ?.* --security-checks .*\b(,?)vuln\b(,?)`],
	"Snyk": [`snyk container`, `snyk monitor`, `snyk test`],
	"Sonatype": [`nancy`, `jake`, `ahab`],
}

vendorToTasks = {
	"Aqua": [{
		"name": "argonsecurity/scanner-action",
		"inputs": {"scanners": ["packages"]},
	}],
	"Trivy": [{"name": "aquasecurity/trivy-action", "inputs": {"security-checks": [`vuln`]}}],
	"Snyk": [{"name": "snyk/actions"}],
}

# Checking if pipeline use argon scanner image with opensource scanner
# Check if the job contains SCANNER env variable
does_use_argon_vuln_scanning {
	job := input[_].contents.jobs[_]
	pipeline.does_runner_match(job, "argonsecurity/scanner")
	pipeline.does_contain_environment_variable(job, "SCANNERS", "packages")
}

# Check if the step runs scan and contains SCANNER env variable
does_use_argon_vuln_scanning {
	job := input[_].contents.jobs[_]
	pipeline.does_runner_match(job, "argonsecurity/scanner")
	step := job.steps[_]
	step.type == "shell"
	step.shell.script == "scan"
	pipeline.does_contain_environment_variable(step, "SCANNERS", "packages")
}

does_use_argon_vuln_scanning {
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
	not does_use_argon_vuln_scanning
	not does_use_command
	not does_use_task

	pipeline := input[i]
	pipeline.contents.jobs[_].metadata.build == true
	not startswith(pipeline.path, "base")

	result := {
		"msg": "No vulnerabilities scanning tool is used in pipeline",
		"filename": pipeline.path,
		"startline": -1,
	}
}
