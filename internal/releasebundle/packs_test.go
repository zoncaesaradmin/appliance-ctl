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
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/geo-zone@sha256:pin"}, PackGeoStack},
		{EntryConfig{Component: "chart", TargetPath: "chart/geo-zone-0.1.0.tgz"}, PackGeoStack},
		{EntryConfig{Component: "appliance", TargetPath: "bin/appliance-host-agentd"}, PackFoundation},
		{EntryConfig{Component: "host-packages", TargetPath: "host-packages/ubuntu/24.04/amd64/avahi-daemon.deb"}, PackFoundation},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/artifact-server@sha256:pin"}, PackStorageNetwork},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-registry-1.tgz"}, PackStorageNetwork},
		{EntryConfig{Component: "oci-images", ImageReference: "registry.local/coredns@sha256:pin"}, PackDeviceUser},
		{EntryConfig{Component: "chart", TargetPath: "chart/appliance-dns-1.tgz"}, PackDeviceUser},
	}
	for _, tc := range cases {
		for _, pack := range []string{PackFoundation, PackAppStack, PackGeoStack, PackStorageNetwork, PackDeviceUser, PackStdLLM, PackOpenWebUI} {
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
