How should we derive security requirements for AI-native software development?

That question led me to build security design review plugins for both Codex and Claude.

I applied the plugin to a public AWS sample architecture and documented, step by step, how security requirements were derived from the service and its operating context.

There are already many security scanners, review tools, and prompts being used in the vibe-coding community. They are valuable, but most of them begin after an implementation or code change already exists.

My view is that security should begin earlier:

```text
service design and operating context
  → security requirements
  → threat model
  → design decisions
  → implementation and security tests
  → evidence and operational detection
```

The plugin can analyze either a written service description or an existing repository. It uses the service's compliance obligations, business requirements, operating environment, organizational controls, and security policies to derive a tailored set of requirements.

The result is intended to become a shared contract for the rest of the lifecycle—not just a checklist for one review:

- requirements for architecture and development
- threats to drive focused security tests
- ownership across the cloud provider, organization, and delivery team
- evidence requirements for later review
- signals that can inform SOC detection and monitoring

I documented the complete nine-part AWS sample exercise here:

https://miata.cloud/tags/security-design/

The plugin repository is available here:

https://github.com/s1ns3nz0/security-requirements

This is an early step toward a broader AI-native security platform—one that connects service context, requirements, threats, implementation evidence, testing, and operations.

#AISecurity #SecurityEngineering #DevSecOps #ThreatModeling #CloudSecurity #AWS #SecurityArchitecture #ComplianceAutomation #Codex #Claude
