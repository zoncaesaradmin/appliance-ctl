package install

import (
	"errors"
	"os"
	"testing"

	"github.com/zoncaesaradmin/appliance-ctl/internal/hostdirs"
	"github.com/zoncaesaradmin/appliance-ctl/internal/runtimeconfig"
	"github.com/zoncaesaradmin/appliance-ctl/internal/state"
)

func TestInferenceJoinGPUValidationUsesJoiningHost(t *testing.T) {
	accelerated := runtimeconfig.Selection{Package: "acc-llm", InferenceEngine: "vllm", Architecture: "amd64"}
	if err := validateInferenceJoinRuntime("inference", accelerated, false); err == nil {
		t.Fatal("accelerated inference worker accepted without local GPU")
	}
	if err := validateInferenceJoinRuntime("inference", accelerated, true); err != nil {
		t.Fatalf("accelerated inference worker rejected with local GPU: %v", err)
	}
	if err := validateInferenceJoinRuntime("worker", runtimeconfig.Selection{}, false); err != nil {
		t.Fatalf("ordinary worker was subjected to inference validation: %v", err)
	}
}

func TestPrepareInferenceWorkerStorageUsesFixedOwnership(t *testing.T) {
	var got struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}
	err := prepareInferenceWorkerStorage(state.NodeRoleInference, func(path string, uid, gid int, mode os.FileMode) error {
		got.path, got.uid, got.gid, got.mode = path, uid, gid, mode
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.path != hostdirs.InferenceModelsDir || got.uid != hostdirs.InferenceDirOwnerUID || got.gid != hostdirs.ApplianceSharedFSGID || got.mode != hostdirs.WorkspaceDirMode {
		t.Fatalf("inference storage preparation = %#v", got)
	}
	if err := prepareInferenceWorkerStorage(state.NodeRoleWorker, nil); err != nil {
		t.Fatalf("ordinary worker unexpectedly prepares inference storage: %v", err)
	}
	if err := prepareInferenceWorkerStorage(state.NodeRoleInference, nil); err == nil {
		t.Fatal("inference worker accepted without storage preparation")
	}
	if err := prepareInferenceWorkerStorage(state.NodeRoleInference, func(string, int, int, os.FileMode) error { return errors.New("disk unavailable") }); err == nil {
		t.Fatal("storage preparation error was accepted")
	}
}
