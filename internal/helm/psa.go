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

// RestrictedNamespaceLabels is the Pod Security Admission profile used for
// normal appliance workloads such as the inference runtime.
func RestrictedNamespaceLabels() map[string]string {
	return map[string]string{
		"pod-security.kubernetes.io/enforce": "restricted",
		"pod-security.kubernetes.io/audit":   "restricted",
		"pod-security.kubernetes.io/warn":    "restricted",
	}
}
