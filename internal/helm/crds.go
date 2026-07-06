package helm

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/evidence"
)

// ApplyCRDs applies every CRD manifest in crdDir. kubectl apply is
// declarative and idempotent by construction: re-applying the same
// manifests is always safe. It fails closed if crdDir does not exist.
func (a *Applier) ApplyCRDs(ctx context.Context, crdDir string) (evidence.Check, error) {
	check := evidence.Check{
		ID:              "apply-argo-crds",
		Category:        "k3s",
		Timestamp:       time.Now().UTC(),
		Idempotent:      true,
		SecretsRedacted: true,
	}

	if _, err := os.Stat(crdDir); err != nil {
		check.Status = evidence.StatusFail
		check.Message = fmt.Sprintf("CRD directory not found: %v", err)
		return check, fmt.Errorf("helm: %w", err)
	}

	if _, err := a.Run(ctx, "kubectl", "--kubeconfig", a.Kubeconfig, "apply", "-f", crdDir); err != nil {
		check.Status = evidence.StatusFail
		check.Message = err.Error()
		return check, fmt.Errorf("helm: apply CRDs: %w", err)
	}

	check.Status = evidence.StatusPass
	check.Message = fmt.Sprintf("CRDs applied from %s", crdDir)
	return check, nil
}
