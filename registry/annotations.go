package registry

const (
	AnnotationBashbrewArch = "com.docker.official-images.bashbrew.arch"

	AnnotationBashbrewSignedByLabel = "com.docker.official-images.bashbrew.signed-by.label"
	AnnotationBashbrewSignedByPEM   = "com.docker.official-images.bashbrew.signed-by.pem"

	// https://github.com/moby/buildkit/blob/c6145c2423de48f891862ac02f9b2653864d3c9e/docs/attestations/attestation-storage.md
	AnnotationBuildkitReferenceType            = "vnd.docker.reference.type"
	AnnotationBuildkitReferenceTypeAttestation = "attestation-manifest"
	AnnotationBuildkitReferenceDigest          = "vnd.docker.reference.digest"

	// https://github.com/distribution/distribution/blob/v3.0.0/docs/content/spec/manifest-v2-2.md
	mediaTypeDockerManifestList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeDockerImageManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerImageConfig   = "application/vnd.docker.container.image.v1+json"

	// https://github.com/sigstore/cosign/blob/v2.5.0/internal/pkg/oci/remote/remote.go#L22-L25
	ArtifactTypeCosignSignature = "application/vnd.dev.cosign.artifact.sig.v1+json"
	// https://github.com/sigstore/cosign/blob/v2.5.0/specs/SIGNATURE_SPEC.md
	MediaTypeCosignSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	AnnotationCosignSignature    = "dev.cosignproject.cosign/signature"
)
