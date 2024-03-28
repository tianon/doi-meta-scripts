# see also "doi.jq" (which this is a "Tianon" replacement for)

# https://github.com/docker-library/meta-scripts/pull/61
# https://slsa.dev/provenance/v0.2#builder.id
def buildkit_provenance_builder_id:
	"https://tianon.xyz"
;

# input: "build" object (with "buildId" top level key)
# output: boolean
def build_should_sbom:
	false
;

# (not currently used by "meta.jq" but included for completeness)
# input: "build" object (with "buildId" top level key)
# output: boolean
def build_should_sign:
	false
;
