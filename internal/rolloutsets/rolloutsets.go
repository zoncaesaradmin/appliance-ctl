package rolloutsets

const (
	AceInfraReleaseName           = "appliance-ace-infra"
	AceAppCoreReleaseName         = "appliance-ace-app-core"
	AceAppsReleaseName            = "appliance-ace-apps"
	ApplicationSupportReleaseName = "appliance-application-support"
	DNSSupportReleaseName         = "appliance-dns-support"
)

func AceSystemOverlay() map[string]any {
	return rolloutOverlay(false, true, false, false, false, false)
}

func AceInfraOverlay() map[string]any {
	overlay := rolloutOverlay(true, false, false, false, false, false)
	overlay["infraNamespace"] = map[string]any{"create": false, "name": "ace-infra"}
	return overlay
}

func AceAppCoreOverlay() map[string]any {
	overlay := rolloutOverlay(false, false, true, false, false, false)
	overlay["appCoreNamespace"] = map[string]any{"create": false, "name": "ace-app-core"}
	return overlay
}

func AceAppsOverlay() map[string]any {
	return rolloutOverlay(false, false, false, true, false, false)
}

func ApplicationSupportOverlay() map[string]any {
	return rolloutOverlay(false, false, false, false, true, false)
}

func DNSSupportOverlay() map[string]any {
	return rolloutOverlay(false, false, false, false, false, true)
}

func rolloutOverlay(aceInfra, aceSystem, aceAppCore, aceApps, applicationSupport, dnsSupport bool) map[string]any {
	return map[string]any{
		"rollout": map[string]any{
			"aceInfra":           map[string]any{"enabled": aceInfra},
			"aceSystem":          map[string]any{"enabled": aceSystem},
			"aceAppCore":         map[string]any{"enabled": aceAppCore},
			"aceApps":            map[string]any{"enabled": aceApps},
			"applicationSupport": map[string]any{"enabled": applicationSupport},
			"dnsSupport":         map[string]any{"enabled": dnsSupport},
		},
	}
}
