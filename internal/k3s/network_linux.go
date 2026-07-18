//go:build linux

package k3s

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func deleteNetworkInterface(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "link", "delete", name).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "Cannot find device") || strings.Contains(msg, "does not exist") {
			return nil
		}
		return fmt.Errorf("k3s: delete network interface %s: %w: %s", name, err, msg)
	}
	return nil
}
