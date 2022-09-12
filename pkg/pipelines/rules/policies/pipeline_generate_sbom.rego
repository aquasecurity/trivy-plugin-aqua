package builtin.pipeline.SBOM_GENERATION

import data.lib.pipeline

__rego_metadata__ := {
	"id": "PIPELINE-0022",
	"avd_id": "AVD-PIPELINE-0022",
	"title": "Ensure pipeline steps produce an SBOM",
	"severity": "HIGH",
	"type": "Pipeline Yaml Security Check",
	"description": "SBOM (Software Bill Of Materials) is a file that specifies each component of software or a build process. Generate an SBOM after each run of a pipeline.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

vendorToCommandRegexes = {
	"Trivy": [`(\.\/)?trivy .* --format cyclonedx`],
	"Aqua": [`(\.\/)?billy generate`],
	"Anchore": [`syft .*`],
	"Cyclonedx": [`cyclonedx-\w+`],
	"Spdx": [`spdx-sbom-generator`],
	"Sonatype": [`jake sbom`],
}

vendorToTasks = {
	"Aqua": [{
		"name": "argonsecurity/actions/generate-manifest",
	}],
	"Anchore": [{
		"name": "anchore/sbom-action",
	}],
	"CycloneDX": [{"name": `CycloneDX/gh-\w+-generate-sbom`}],
}

does_use_command {
	job := input.jobs[_]
	regexes := vendorToCommandRegexes[vendor]
	pipeline.does_contains_one_of_commands(job, regexes)
}

does_use_task {
	job := input.jobs[_]
	step := job.steps[_]
	step.type == "task"
	pipeline.does_task_match(step.task, vendorToTasks)
}

deny[result] {
	not does_use_command
	not does_use_task

	input.jobs[i].metadata.build == true

	result := {
		"msg": sprintf("Consider adding SBOM generation tool in build job '%s'", input.jobs[i].name),
		"startline": input.jobs[i].file_reference.start_ref.line,
	}
}
