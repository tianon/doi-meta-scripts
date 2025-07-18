include "deploy";

# just amd64 arch-specific manifests
arch_filter_builds("amd64")
| arch_tagged_manifests
# ... converted into a list of canonical inputs for "cmd/deploy"
| [ tagged_deploy_objects ]
