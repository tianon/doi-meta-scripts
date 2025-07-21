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
	if env.BASHBREW_META_SCRIPTS_RUNNING_TESTS == "vigorously" then
		input_filename
		| contains("/oci-import/")
		| not
	else
		# TODO if normalized_builder is classic, we can't currently sign those builds (but normalized_builder is defined in meta.jq so we'd have to pull that out to use it here, which is sane but ENAMING)
		.source.entries[0].Builder != "classic"
		and (.build.arch | startswith("windows-") | not)
		and env.BASHBREW_META_SCRIPTS_RUNNING_TESTS != "vigorously"
	end
;

# input: "build" object (with "buildId" top level key)
# output: key-value of (architecture trust-boundary specific) public keys (in PEM format) that should be used to verify the validity of a given build (labelled with a superfluous name for our sake / to be embedded in "builds.json" so it's easier to identify which images are signed by a given key, especially during rotation periods)
# - might (likely) have extraneous whitespace that should be trimmed/ignored for valid PEM parsing
# - empty object or empty string means "no signature" should be considered valid
def build_arch_sign_public_keys:
	if build_should_sign then
		{
			"YubiKey 4239413 Slot 82": "
				-----BEGIN PUBLIC KEY-----
				MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG+1HMsDDAFXQrPkPi80/P4XmMsWJ
				dD5BxdeI7uvLPArqhqsB38LcTLiZ2iTwiITRwyqHlbnjXdvByWJAdaUWNQ==
				-----END PUBLIC KEY-----
			",
			"unsigned": "", # don't immediately rebuild everything
		}
	else {} end
;
