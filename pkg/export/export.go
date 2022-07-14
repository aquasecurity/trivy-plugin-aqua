package export

import (
	"encoding/json"
	"os"

	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

type File struct {
	Report  *types.Report           `json:"Report"`
	Results []*buildsecurity.Result `json:"Results"`
}

func AssuranceData(path string, report *types.Report, results []*buildsecurity.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return json.NewEncoder(f).Encode(File{
		Report:  report,
		Results: results,
	})
}
