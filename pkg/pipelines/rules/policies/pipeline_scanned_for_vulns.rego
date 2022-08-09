package builtin.pipeline.ID9

__rego_metadata__ := {
	"id": "ID9",
	"avd_id": "",
	"title": "Ensure pipelines are automatically scanned for vulnerabilities",
	"severity": "HIGH",
	"type": "Pipeline Yaml Security Check",
	"description": "Scan pipelines for vulnerabilities. It is recommended to do that automatically",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "pipeline"}],
}

# does_job_contain_one_of_tasks(job, regexes) {
# 	job.steps[i].type == "task"
# 	regex.match(regexes[_], job.steps[i].task.name)
# }

# is_pipeline_scaning_tasks_missing {
# 	count({job | job := input[_].Content.jobs[_]; does_job_contain_one_of_tasks(job, constsLib.pipeline_vulnerability_scan_tasks)}) == 0
# }

# # Pin actions to a full length commit SHA
# deny[result] {
# 	is_pipeline_scaning_tasks_missing
# 	result := {"msg": "Consider adding a pipeline task to scan for vulnerabilities"}
# }
