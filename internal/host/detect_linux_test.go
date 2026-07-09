//go:build linux

package host

import (
	"reflect"
	"testing"
)

func TestRequiredUFWRules(t *testing.T) {
	got := requiredUFWRules([]int{6443, 10250, 8472})
	want := []string{"6443/tcp", "10250/tcp", "8472/udp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requiredUFWRules: got %v want %v", got, want)
	}
}

func TestMissingUFWRules(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
6443/tcp                   ALLOW       Anywhere
10250/tcp                  ALLOW       Anywhere
8472/udp                   ALLOW       Anywhere
`

	if got := missingUFWRules(status, []int{6443, 10250, 8472}); len(got) != 0 {
		t.Fatalf("missingUFWRules: expected no missing rules, got %v", got)
	}
}

func TestMissingUFWRulesAcceptsBarePortRule(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
6443                       ALLOW       Anywhere
10250                      ALLOW       Anywhere
8472/udp                   ALLOW       Anywhere
`

	if got := missingUFWRules(status, []int{6443, 10250, 8472}); len(got) != 0 {
		t.Fatalf("missingUFWRules: expected no missing rules for bare tcp ports, got %v", got)
	}
}

func TestMissingUFWRulesReportsMissingEntries(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
6443/tcp                   ALLOW       Anywhere
`

	got := missingUFWRules(status, []int{6443, 10250, 8472})
	want := []string{"10250/tcp", "8472/udp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missingUFWRules: got %v want %v", got, want)
	}
}
