package releasebundle

import (
	"strings"
	"testing"
)

func TestDeliveryPacksAreDisjoint(t *testing.T) {
	cases := []struct {
		entry EntryConfig
		pack  string
	}{
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/inference-runtime@sha256:pin"}, PackStdLLM},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-inference-0.9.0.tgz"}, PackStdLLM},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/open-webui@sha256:pin"}, PackOpenWebUI},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/open-webui-gateway@sha256:pin"}, PackOpenWebUI},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/channel-integration@sha256:pin"}, PackAppStack},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/ordering@sha256:pin"}, PackAppStack},
		{EntryConfig{Component: "appliance", TargetPath: "bin/appliance-host-agentd"}, PackFoundation},
		{EntryConfig{Component: "host-packages", TargetPath: "host-packages/ubuntu/24.04/amd64/avahi-daemon.deb"}, PackFoundation},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/artifact-server@sha256:pin"}, PackStorageNetwork},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-registry-1.tgz"}, PackStorageNetwork},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/coredns@sha256:pin"}, PackDeviceUser},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-dns-1.tgz"}, PackDeviceUser},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workspace-provisioner@sha256:pin"}, PackBuildWorkflows},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workflow-controller@sha256:pin"}, PackBuildWorkflows},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workflow-executor@sha256:pin"}, PackBuildWorkflows},
		{EntryConfig{Component: "chart", TargetPath: "chart/argo-workflows-1.tgz"}, PackBuildWorkflows},
		{EntryConfig{Component: "kubernetes-crds", TargetPath: "kubernetes/crds/workflows.yaml"}, PackBuildWorkflows},
	}
	for _, tc := range cases {
		for _, pack := range []string{PackFoundation, PackAppStack, PackStorageNetwork, PackBuildWorkflows, PackDeviceUser, PackStdLLM, PackOpenWebUI} {
			if got := entryBelongsToPack(tc.entry, pack); got != (pack == tc.pack) {
				t.Errorf("entry %+v belongs to %s = %v, want owner %s", tc.entry, pack, got, tc.pack)
			}
		}
	}
}

func TestAppStackPackRequiresItsServices(t *testing.T) {
	if err := validateInstallableBundle(nil, PackAppStack); err == nil {
		t.Fatal("empty app-stack pack accepted")
	}
	entries := []manifestEntry{
		{Component: "oci-images", ImageReference: "registry.local/channel-integration@sha256:" + strings.Repeat("a", 64)},
		{Component: "oci-images", ImageReference: "registry.local/ordering@sha256:" + strings.Repeat("b", 64)},
	}
	if err := validateInstallableBundle(entries, PackAppStack); err != nil {
		t.Fatalf("complete app-stack pack rejected: %v", err)
	}
}

func TestStorageNetworkPackRequiresItsServices(t *testing.T) {
	if err := validateInstallableBundle(nil, PackStorageNetwork); err == nil {
		t.Fatal("empty storage-network pack accepted")
	}
}

func TestBuildWorkflowsPackRequiresItsServices(t *testing.T) {
	if err := validateInstallableBundle(nil, PackBuildWorkflows); err == nil {
		t.Fatal("empty build-workflows pack accepted")
	}
}
