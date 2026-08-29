package rolloutsets

const (
	AceInfraReleaseName           = "appliance-ace-infra"
	AceAppsReleaseName            = "appliance-ace-apps"
	ApplicationSupportReleaseName = "appliance-application-support"
	DNSSupportReleaseName         = "appliance-dns-support"
	WorkflowsSupportReleaseName   = "appliance-workflows-support"
)

func AceSystemOverlay() map[string]any {
	return rolloutOverlay(false, true, false, false, false, false)
}

func AceInfraOverlay() map[string]any {
	return rolloutOverlay(true, false, false, false, false, false)
}

func AceAppsOverlay() map[string]any {
	return rolloutOverlay(false, false, true, false, false, false)
}

func ApplicationSupportOverlay() map[string]any {
	return rolloutOverlay(false, false, false, true, false, false)
}

func DNSSupportOverlay() map[string]any {
	return rolloutOverlay(false, false, false, false, true, false)
}

func WorkflowsSupportOverlay() map[string]any {
	return rolloutOverlay(false, false, false, false, false, true)
}

func rolloutOverlay(aceInfra, aceSystem, aceApps, applicationSupport, dnsSupport, workflowsSupport bool) map[string]any {
	return map[string]any{
		"rollout": map[string]any{
			"aceInfra":           map[string]any{"enabled": aceInfra},
			"aceSystem":          map[string]any{"enabled": aceSystem},
			"aceApps":            map[string]any{"enabled": aceApps},
			"applicationSupport": map[string]any{"enabled": applicationSupport},
			"dnsSupport":         map[string]any{"enabled": dnsSupport},
			"workflowsSupport":   map[string]any{"enabled": workflowsSupport},
		},
	}
}
