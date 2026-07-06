package upgrade

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.0", "2.4.0", 0},
		{"2.3.0", "2.4.0", -1},
		{"2.4.0", "2.3.0", 1},
		{"2.4.1", "2.4.0", 1},
		{"3.5.2", "3.5.10", -1},
		{"3.5.2-rc1", "3.5.2", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsDowngrade(t *testing.T) {
	if !isDowngrade("3.5.2", "3.5.1") {
		t.Error("expected 3.5.1 to be a downgrade from 3.5.2")
	}
	if isDowngrade("3.5.2", "3.6.0") {
		t.Error("expected 3.6.0 not to be a downgrade from 3.5.2")
	}
	if isDowngrade("3.5.2", "3.5.2") {
		t.Error("expected the same version not to be a downgrade")
	}
}

func TestIsSupportedSource(t *testing.T) {
	supported := []string{"2.3.0", "2.3.1"}
	if !isSupportedSource("2.3.1", supported) {
		t.Error("expected 2.3.1 to be a supported source")
	}
	if isSupportedSource("2.2.0", supported) {
		t.Error("expected 2.2.0 not to be a supported source")
	}
}
