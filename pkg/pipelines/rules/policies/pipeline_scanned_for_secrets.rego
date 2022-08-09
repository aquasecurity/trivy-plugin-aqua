package builtin.pipeline.ID10

__rego_metadata__ := {
	"id": "ID10",
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

# secret_scan_commands = [
# 	`spectral.* scan`,
# 	`git secrets --scan`,
# 	`whispers`,
# 	`docker run.* abhartiya/tools_gitallsecrets`,
# 	`detect-secrets.* scan`,
# ]

# does_job_contain_one_of_tasks(job, regexes) {
# 	job.steps[i].type == "task"
# 	regex.match(regexes[_], job.steps[i].task.name)
# }

# does_job_contain_one_of_shell_commands(job, regexes) {
# 	job.steps[i].type == "shell"
# 	r := regexes[_]
# 	regex.match(r, job.steps[i].shell.script)
# }

# is_repository_scanning_tasks_missing {
# 	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_tasks(job, constsLib.secret_scan_tasks)}) == 0
# 	count({job | job := input.Pipelines[_].jobs[_]; does_job_contain_one_of_shell_commands(job, secret_scan_commands)}) == 0
# }

# deny[msg] {
# 	is_repository_scanning_tasks_missing
# 	msg := sprintf("Pipeline file %v does not contain any scanning tasks", [input.Pipelines[_].path])
# }
