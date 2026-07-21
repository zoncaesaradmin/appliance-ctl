package k3s

import "fmt"

// UnitConfig describes the release-owned systemd unit for the K3s
// server. There is deliberately no ExecStartPre download step and no
// auto-upgrade hook: the binary and config are already staged from the
// bundle, and "K3s auto-upgrade is disabled unless a later signed
// appliance release explicitly orchestrates it."
type UnitConfig struct {
	BinaryPath string
	ConfigPath string
}

const unitTemplate = `[Unit]
Description=Appliance-managed K3s server (release-owned; do not edit)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=%s server --config %s
# KillMode=process matches upstream K3s: stopping the unit must not
# tear down running pods during a binary upgrade. Uninstall/rollback
# paths MUST call CleanupNodeNetwork afterward to reap orphaned
# containerd-shim processes; otherwise the next start inherits a
# split-brain runtime and ClusterIP routing breaks.
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`

// Render produces the k3s.service unit file content.
func (u UnitConfig) Render() string {
	return fmt.Sprintf(unitTemplate, u.BinaryPath, u.ConfigPath)
}
