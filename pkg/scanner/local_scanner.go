package scanner

import (
	"encoding/json"
	"io/ioutil"

	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	localscanner "github.com/aquasecurity/trivy/pkg/scanner/local"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/result"

	"github.com/aquasecurity/trivy/pkg/scanner"
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

func (s aquaScanner) Scan(target, imageID string, layerIDs []string, options types.ScanOptions) (
	types.Results, *ftypes.OS, error) {

	results, osFound, err := s.driver.Scan(target, imageID, layerIDs, options)
	if err != nil {
		return nil, osFound, err
	}

	for i := range results {
		s.resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
	}

	file, err := json.MarshalIndent(results, "", " ")
	if err != nil {
		return nil, osFound, err
	}

	err = ioutil.WriteFile(resultsFile, file, 0600)
	if err != nil {
		return nil, osFound, err
	}

	return results, osFound, nil
}
