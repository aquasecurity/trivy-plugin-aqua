package scanner

import (
	"encoding/json"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/result"
	"io/ioutil"

	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/cache"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	localscanner "github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

type aquaScanner struct {
	driver       scanner.Driver
	resultClient result.Client
}

func newAquaScanner(localArtifactCache cache.LocalArtifactCache) aquaScanner {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	lscanner := localscanner.NewScanner(applierApplier, detector)

	return aquaScanner{driver: lscanner, resultClient: result.NewClient(db.Config{})}
}

func (s aquaScanner) Scan(target, imageID string, layerIDs []string, options types.ScanOptions) (report.Results, *ftypes.OS, error) {

	results, osFound, err := s.driver.Scan(target, imageID, layerIDs, options)
	if err != nil {
		return nil, osFound, err
	}
	for i, _ := range results {
		s.resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
	}

	file, err := json.MarshalIndent(results, "", " ")
	if err != nil {
		return nil, osFound, err
	}

	err = ioutil.WriteFile(resultsFile, file, 0644)
	if err != nil {
		return nil, osFound, err
	}

	return results, osFound, nil
}
