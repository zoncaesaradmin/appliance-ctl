//go:build linux

package host

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const ext4SuperMagic = 0xEF53

// Detect gathers real host signals on Linux. It is read-only: it never
// writes, starts, or stops anything. Best-effort signals (time sync,
// firewall, conflicting services) fall back to zero values rather than
// failing the whole detection when a helper command is unavailable.
func Detect(opts Options) (Facts, error) {
	f := Facts{
		Arch:          runtime.GOARCH,
		CPUCount:      runtime.NumCPU(),
		DataDir:       opts.DataDir,
		RequiredPorts: opts.RequiredPorts,
		PortsInUse:    map[int]string{},
		DetectedAt:    time.Now().UTC(),
	}

	f.OS, f.OSVersion = readOSRelease("/etc/os-release")

	if release, err := kernelRelease(); err == nil {
		f.KernelRelease = release
	}

	if total, err := memTotalBytes("/proc/meminfo"); err == nil {
		f.MemTotalBytes = total
	}

	f.CgroupVersion = cgroupVersion()
	f.UserNamespacesEnabled = userNamespacesEnabled()
	f.IPv4ForwardingEnabled = ipv4ForwardingEnabled()

	if opts.DataDir != "" {
		if fsType, freeBytes, freeInodes, err := statDataDir(opts.DataDir); err == nil {
			f.DataDirFilesystem = fsType
			f.DataDirFreeBytes = freeBytes
			f.DataDirFreeInodes = freeInodes
		}
	}

	f.TimeSyncActive = commandOutputEquals("yes", "timedatectl", "show", "-p", "NTPSynchronized", "--value")

	if hostname, err := os.Hostname(); err == nil {
		f.Hostname = hostname
		f.HostnameResolvesInternally = hostnameResolves(hostname)
	}

	for _, port := range opts.RequiredPorts {
		if owner, inUse := portInUse(port); inUse {
			f.PortsInUse[port] = owner
		}
	}

	f.FirewallActive, f.FirewallName, f.FirewallMissingRules = detectFirewall(opts.RequiredPorts)
	f.ConflictingServices = detectConflictingServices()

	return f, nil
}

func readOSRelease(path string) (id, versionID string) {
	file, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "VERSION_ID="):
			versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return id, versionID
}

func kernelRelease() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", err
	}
	return charsToString(uname.Release[:]), nil
}

func charsToString(chars []int8) string {
	buf := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

func memTotalBytes(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil
		}
	}
	return 0, fmt.Errorf("host: MemTotal not found in %s", path)
}

func cgroupVersion() int {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return 2
	}
	if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		return 1
	}
	return 0
}

func userNamespacesEnabled() bool {
	data, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err != nil {
		return false
	}
	max, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return err == nil && max > 0
}

func ipv4ForwardingEnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(data)) == "1"
}

func statDataDir(dir string) (fsType string, freeBytes uint64, freeInodes uint64, err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", 0, 0, err
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return "", 0, 0, err
	}

	fsType = filesystemTypeName(stat.Type)
	freeBytes = uint64(stat.Bfree) * uint64(stat.Bsize)
	freeInodes = stat.Ffree
	return fsType, freeBytes, freeInodes, nil
}

func filesystemTypeName(magic int64) string {
	if magic == ext4SuperMagic {
		return "ext4"
	}
	return fmt.Sprintf("unknown(0x%x)", magic)
}

func commandOutputEquals(want string, name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == want

}

func serviceIsActive(unit string) bool {
	return commandOutputEquals("active", "systemctl", "is-active", unit)
}

func hostnameResolves(hostname string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, hostname)
	return err == nil
}

func portInUse(port int) (owner string, inUse bool) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "unknown (already bound)", true
	}
	_ = ln.Close()
	return "", false
}

func detectFirewall(requiredPorts []int) (active bool, name string, missingRules []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if out, err := exec.CommandContext(ctx, "ufw", "status").Output(); err == nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "inactive") {
			return false, "ufw", nil
		}
		if strings.Contains(lower, "active") {
			return true, "ufw", missingUFWRules(string(out), requiredPorts)
		}
		return false, "ufw", nil
	}
	if serviceIsActive("nftables") {
		return true, "nftables", nil
	}
	if serviceIsActive("firewalld") {
		return true, "firewalld", nil
	}
	return false, "", nil
}

func missingUFWRules(statusOutput string, requiredPorts []int) []string {
	allowed := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(statusOutput))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		rule := strings.ToLower(fields[0])
		action := strings.ToUpper(fields[1])
		if action != "ALLOW" {
			continue
		}
		allowed[rule] = true
	}

	var missing []string
	for _, rule := range requiredUFWRules(requiredPorts) {
		if !allowed[rule] && !allowed[strings.Split(rule, "/")[0]] {
			missing = append(missing, rule)
		}
	}
	return missing
}

func requiredUFWRules(requiredPorts []int) []string {
	rules := make([]string, 0, len(requiredPorts))
	for _, port := range requiredPorts {
		switch port {
		case 8472:
			rules = append(rules, "8472/udp")
		default:
			rules = append(rules, fmt.Sprintf("%d/tcp", port))
		}
	}
	return rules
}

func detectConflictingServices() []string {
	candidates := []string{"docker", "microk8s", "kubelet"}
	var active []string
	for _, svc := range candidates {
		if serviceIsActive(svc) {
			active = append(active, svc)
		}
	}
	return active
}
