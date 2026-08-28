package productconfig_test

import "github.com/zoncaesaradmin/appliance-ctl/internal/productconfig"

// testProfileCatalog is intentionally test-only. Production profile policy is
// read exclusively from the signed metadata bundle.
func testProfileCatalog() productconfig.ProfileCatalog {
	return productconfig.ProfileCatalog{
		productconfig.ProfileCore:                       {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityFiles}},
		productconfig.ProfileBuilder:                    {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityWorkflows, productconfig.CapabilityBuild, productconfig.CapabilityArtifact}},
		productconfig.ProfileStorage:                    {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityArtifact}},
		productconfig.ProfileLANDNS:                     {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityDNS}},
		productconfig.ProfileStorageLANDNS:              {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityArtifact, productconfig.CapabilityDNS}},
		productconfig.ProfileBuilderLANDNS:              {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityWorkflows, productconfig.CapabilityBuild, productconfig.CapabilityArtifact, productconfig.CapabilityDNS}},
		productconfig.ProfileBuilderLANLLM:              {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityWorkflows, productconfig.CapabilityBuild, productconfig.CapabilityArtifact, productconfig.CapabilityInference}},
		productconfig.ProfileBuilderLANLLMStorageLANDNS: {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityWorkflows, productconfig.CapabilityBuild, productconfig.CapabilityArtifact, productconfig.CapabilityDNS, productconfig.CapabilityInference}},
		productconfig.ProfileLANLLM:                     {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityInference}},
		productconfig.ProfileTraining:                   {Capabilities: []productconfig.Capability{productconfig.CapabilityBase, productconfig.CapabilityHost, productconfig.CapabilityFiles, productconfig.CapabilityVideo}},
	}
}
