package releasebundle

import "testing"

func TestDeliveryPacksAreDisjoint(t *testing.T) {
	cases := []struct {
		entry EntryConfig
		pack  string
	}{
		{EntryConfig{Component: "appliance", TargetPath: "bin/appliance-host-agentd"}, PackFoundation},
		{EntryConfig{Component: "host-packages", TargetPath: "host-packages/ubuntu/24.04/amd64/avahi-daemon.deb"}, PackFoundation},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/artifact-server@sha256:pin"}, PackDevPlatform},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/coredns@sha256:pin"}, PackDevPlatform},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-registry-1.tgz"}, PackDevPlatform},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-dns-1.tgz"}, PackDevPlatform},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workspace-provisioner@sha256:pin"}, PackDevPlatform},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workflow-controller@sha256:pin"}, PackDevPlatform},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/workflow-executor@sha256:pin"}, PackDevPlatform},
		{EntryConfig{Component: "chart", TargetPath: "chart/argo-workflows-1.tgz"}, PackDevPlatform},
		{EntryConfig{Component: "kubernetes-crds", TargetPath: "kubernetes/crds/workflows.yaml"}, PackDevPlatform},
	}
	for _, tc := range cases {
		for _, pack := range []string{PackFoundation, PackDevPlatform, PackDeviceUser, PackInference} {
			if got := entryBelongsToPack(tc.entry, pack); got != (pack == tc.pack) {
				t.Errorf("entry %+v belongs to %s = %v, want owner %s", tc.entry, pack, got, tc.pack)
			}
		}
	}
}

func TestDevPlatformPackRequiresItsServices(t *testing.T) {
	if err := validateInstallableBundle(nil, PackDevPlatform); err == nil {
		t.Fatal("empty dev-platform pack accepted")
	}
}
