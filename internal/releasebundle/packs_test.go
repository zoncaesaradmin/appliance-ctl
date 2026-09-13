package releasebundle

import "testing"

func TestDeliveryPacksAreDisjoint(t *testing.T) {
	cases := []struct {
		entry EntryConfig
		pack  string
	}{
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/artifact-server@sha256:pin"}, PackStorageNetwork},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/coredns@sha256:pin"}, PackStorageNetwork},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-registry-1.tgz"}, PackStorageNetwork},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-dns-1.tgz"}, PackStorageNetwork},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workspace-provisioner@sha256:pin"}, PackBuildWorkflows},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workflow-controller@sha256:pin"}, PackBuildWorkflows},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workflow-executor@sha256:pin"}, PackBuildWorkflows},
		{EntryConfig{Component: "chart", TargetPath: "chart/argo-workflows-1.tgz"}, PackBuildWorkflows},
		{EntryConfig{Component: "kubernetes-crds", TargetPath: "kubernetes/crds/workflows.yaml"}, PackBuildWorkflows},
	}
	for _, tc := range cases {
		for _, pack := range []string{PackFoundation, PackStorageNetwork, PackBuildWorkflows, PackDeviceUser, PackInference} {
			if got := entryBelongsToPack(tc.entry, pack); got != (pack == tc.pack) {
				t.Errorf("entry %+v belongs to %s = %v, want owner %s", tc.entry, pack, got, tc.pack)
			}
		}
	}
}

func TestStorageNetworkPackRequiresBothServices(t *testing.T) {
	if err := validateInstallableBundle(nil, PackStorageNetwork); err == nil {
		t.Fatal("empty storage-network pack accepted")
	}
}
