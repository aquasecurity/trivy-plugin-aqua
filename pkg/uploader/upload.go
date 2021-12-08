package uploader

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

// Upload forwards the results to the configured client
func Upload(client buildClient.Client, results []*buildsecurity.Result, policyFailures []*buildsecurity.PolicyFailure, tags map[string]string) error {
	log.Logger.Debugf("Uploading scan with tags. %v", tags)
	return client.Upload(results, policyFailures, tags)
}
