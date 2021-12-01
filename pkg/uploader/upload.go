package uploader

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

// Upload forwards the results to the configured client
func Upload(client buildClient.Client, results []*buildsecurity.Result) error {
	return client.Upload(results)
}
