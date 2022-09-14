package builtin.pipeline.DE_PINNED_VERSION

import data.lib.pipeline

__rego_metadata__ := {
	"id": "PIPELINE-0008",
	"avd_id": "AVD-PIPELINE-0008",
	"title": "Unrestricted dependency version",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "Pinning a dependency to a full length commit SHA or a full semver if SHA is not available is currently the only way to use dependencies as immutable releases. Pinning to a particular SHA helps mitigate the risk of a bad actor adding a backdoor to the dependency's repository, as they would need to generate a SHA-1 collision for a valid Git object payload.  Although pinning to a commit SHA is the most secure option, specifying a tag is more convenient and is widely used. If you'd like to specify a tag, then be sure that you trust the dependency's creators. Note that there is risk to this approach even if you trust the author, because a tag can be moved or deleted if a bad actor gains access to the repository storing the dependency source code.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Pin dependecies to a full length commit SHA
deny[result] {
	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.version_type != "commit"
	result := {
		"msg": sprintf("Dependecy %s version %s should be pinned to the commit sha", [input.jobs[i].steps[j].task.name, input.jobs[i].steps[j].task.version]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
