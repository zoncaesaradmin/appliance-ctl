package helm

// PrivilegedNamespaceLabels is the Pod Security Admission exception used for
// hostNetwork workloads such as LAN DNS (CoreDNS on :53).
func PrivilegedNamespaceLabels() map[string]string {
	return map[string]string{
		"pod-security.kubernetes.io/enforce": "privileged",
		"pod-security.kubernetes.io/audit":   "privileged",
		"pod-security.kubernetes.io/warn":    "privileged",
	}
}
