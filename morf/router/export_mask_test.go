package router

import (
	"strings"
	"testing"

	"morf/models"
	"morf/report"
	"morf/utils"
)

// TestExportMaskingComposition guards the security fix that /results/:jobID/export
// must not leak RAW secret values in json/csv/pdf output. It reproduces exactly
// what the export handler does — report.MaskResultJSON on job.Result, then
// utils.ExportResult — and asserts the planted plaintext key is absent from both
// the JSON and CSV exports while the masked ellipsis is present.
func TestExportMaskingComposition(t *testing.T) {
	const planted = "AKIAIOSFODNN7EXAMPLE"
	raw := `{"data":{"fileName":"app.apk","packageName":"com.x","secrets":[` +
		`{"secretType":"AWS Access Key","secretString":"` + planted + `","fileLocation":"a.smali","lineNo":3}]}}`

	masked, err := report.MaskResultJSON([]byte(raw))
	if err != nil {
		t.Fatalf("MaskResultJSON: %v", err)
	}
	job := &models.ScanJob{Result: string(masked)}

	for _, format := range []utils.ExportFormat{utils.ExportFormatJSON, utils.ExportFormatCSV} {
		out, _, err := utils.ExportResult(job, format)
		if err != nil {
			t.Fatalf("ExportResult(%s): %v", format, err)
		}
		if strings.Contains(string(out), planted) {
			t.Errorf("export format %s LEAKED the raw secret %q", format, planted)
		}
		if !strings.Contains(string(out), "…") {
			t.Errorf("export format %s missing masked value (no ellipsis)", format)
		}
	}
}
