# see also "doi.jq" (which this is a "Tianon" replacement for)

# https://github.com/docker-library/meta-scripts/pull/61
# https://slsa.dev/provenance/v0.2#builder.id
def buildkit_provenance_builder_id:
	"https://tianon.xyz"
;

# input: "build" object (with "buildId" top level key)
# output: boolean
def build_should_sbom:
	any(.source.arches[.build.arch].tags[]; IN("tianon/test:doi-sbom"))
	# (this could be implemented fully with "IN()" but I want it to stay general so I can make it more advanced/extreme easily without a full refactor)
;

# input: "build" object (with "buildId" top level key)
# output: boolean
def build_should_sign:
	any(.source.arches[.build.arch].tags[]; IN("tianon/test:doi-sign"))
;
