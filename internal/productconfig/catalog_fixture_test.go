package productconfig_test

import "github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"

// testProfileCatalog is intentionally test-only. Production profile policy is
// read exclusively from the signed metadata bundle.
func testProfileCatalog() productconfig.ProfileCatalog {
	return productconfig.ProfileCatalog{
		productconfig.ProfileCore:          {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityActions, productconfig.CapabilityLANDiscovery, productconfig.CapabilityFiles}},
		productconfig.ProfileStorage:       {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityActions, productconfig.CapabilityLANDiscovery, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityArtifact}},
		productconfig.ProfileLANDNS:        {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityActions, productconfig.CapabilityLANDiscovery, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityDNS}},
		productconfig.ProfileStorageLANDNS: {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityActions, productconfig.CapabilityLANDiscovery, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityArtifact, productconfig.CapabilityDNS}},
		productconfig.ProfileLANLLM:        {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityActions, productconfig.CapabilityLANDiscovery, productconfig.CapabilityInference, productconfig.CapabilityOpenWebUI}},
		productconfig.ProfileTraining:      {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityActions, productconfig.CapabilityLANDiscovery, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityVideo, productconfig.CapabilityApplications, productconfig.CapabilityPlaintextHTTP}},
	}
}
