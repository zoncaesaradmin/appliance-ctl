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

func TestIsKubePodCgroup(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "cgroup v2 kubepods",
			raw:  "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod282cfd9c_5ec9_434e_b4b8_3cd379bda4c4.slice/cri-containerd-abc.scope\n",
			want: true,
		},
		{
			name: "user session",
			raw:  "0::/user.slice/user-1000.slice/session-1.scope\n",
			want: false,
		},
		{
			name: "cgroup v1 kubepods",
			raw:  "12:devices:/kubepods/burstable/podabc/containerxyz\n",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isKubePodCgroup([]byte(tc.raw)); got != tc.want {
				t.Fatalf("isKubePodCgroup(%q)=%v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
