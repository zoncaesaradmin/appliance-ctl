//go:build linux

package k3s

import "testing"

func TestIsK3sContainerdShimCmdline(t *testing.T) {
	cases := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{
			name:    "k3s shim",
			cmdline: "containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-address\x00/run/k3s/containerd/containerd.sock\x00",
			want:    true,
		},
		{
			name:    "unrelated shim",
			cmdline: "containerd-shim-runc-v2\x00-address\x00/run/containerd/containerd.sock\x00",
			want:    false,
		},
		{
			name:    "non-shim process",
			cmdline: "/usr/bin/coredns\x00-conf\x00/etc/coredns/Corefile\x00",
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isK3sContainerdShimCmdline([]byte(tc.cmdline)); got != tc.want {
				t.Fatalf("isK3sContainerdShimCmdline(%q)=%v, want %v", tc.cmdline, got, tc.want)
			}
		})
	}
}
