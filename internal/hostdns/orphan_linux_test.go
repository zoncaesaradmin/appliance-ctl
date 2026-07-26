//go:build linux

package hostdns

import "testing"

func TestIsApplianceCoreDNSCmdline(t *testing.T) {
	cases := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{
			name:    "appliance dns",
			cmdline: "/coredns\x00-conf\x00/etc/coredns/Corefile\x00",
			want:    true,
		},
		{
			name:    "unrelated",
			cmdline: "/usr/bin/python3\x00-m\x00http.server\x00",
			want:    false,
		},
		{
			name:    "coredns without conf is ignored",
			cmdline: "/usr/local/bin/coredns\x00",
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isApplianceCoreDNSCmdline([]byte(tc.cmdline)); got != tc.want {
				t.Fatalf("isApplianceCoreDNSCmdline(%q)=%v, want %v", tc.cmdline, got, tc.want)
			}
		})
	}
}

func TestProcessUID(t *testing.T) {
	status := []byte("Name:\tcoredns\nUmask:\t0022\nUid:\t10004\t10004\t10004\t10004\nGid:\t20000\t20000\t20000\t20000\n")
	if got := processUID(status); got != 10004 {
		t.Fatalf("processUID=%d, want 10004", got)
	}
}
