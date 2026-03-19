include "oci";

# input: array of "build" objects (with "buildId" top level keys)
# output: array of "build" objects (with "buildId" top level keys) filtered by "builds_selector"
def filter_builds(builds_selector):
	map_values(select(builds_selector))
;
def arch_filter_builds($arch):
	filter_builds(.build.arch == $arch)
;

# input: array of "build" objects (with "buildId" top level keys), possibly filtered by filter_builds
# output: map of { "tag": [ list of OCI descriptors ], ... }
def tagged_manifests(tags_extractor):
	reduce (.[] | select(.build.resolved)) as $i ({};
		.[
			$i
			| tags_extractor
			| ..|strings # no matter what "tags_extractor" gives us, this will flatten us to a stream of strings
		] += [
			# as an extra protection against cross-architecture "bleeding" ("riscv64" infra pushing "amd64" images, for example), filter the list of manifests to those whose architecture matches the architecture it is supposed to be for
			# to be explicitly clear, this filtering is *also* done as part of our "builds.json" generation, so this is an added layer of best-effort protection that will be especially important to preserve and/or replicate if/when we solve the "not built yet so include the previous contents of the tag" portion of the problem at this layer instead of in the currently-separate put-shared process
			$i.build.resolved.manifests[]
			| select(
				(.annotations["com.docker.official-images.bashbrew.arch"] // "") == $i.build.arch # this assumes "registry.SynthesizeIndex" created this list of manifests (because it sets this annotation), but it would be reasonable for us to reimplement that conversion of "OCI platform object" to "bashbrew architecture" in pure jq if it was prudent or necessary to do so
				and (.artifactType // "") != media_type_cosign_artifact # do not include signature objects in Hub indexes beyond staging (these are the arch-specific signatures anyhow, so shouldn't be pushed outside staging and are for system-internal provenance verification / chain-of-trust)
			)
		]
	)
;
def arch_tagged_manifests:
	tagged_manifests(.source.arches[.build.arch].archTags)
;

# input: output of tagged_manifests (map of tag -> list of OCI descriptors)
# output: stream of input objects for "cmd/deploy" ({ "type": "manifest", "refs": [ ... ], "data": { ... } })
def tagged_deploy_objects:
	reduce to_entries[] as $in ({};
		$in.key as $ref
		| (
			$in.value
			| map(normalize_descriptor) # normalized platforms *and* normalized field ordering
			| sort_manifests
		) as $manifests
		| ([ $manifests[].digest ] | join("\n")) as $key
		| .[$key] |= (
			if . then
				.refs += [ $ref ]
			else
				{
					type: "manifest",
					refs: [ $ref ],

					# add appropriate "lookup" values for copying child objects properly
					lookup: (
						$manifests
						| map({
							key: .digest,
							value: (
								.digest as $dig
								| .annotations["org.opencontainers.image.ref.name"]
								| rtrimstr("@" + $dig)
							),
						})
						| from_entries
					),

					# convert the list of "manifests" into a full (canonical!) index/manifest list for deploying
					data: {
						schemaVersion: 2,
						mediaType: (
							if $manifests[0].mediaType == media_type_dockerv2_image then
								media_type_dockerv2_list
							else
								media_type_oci_index
							end
						),
						manifests: (
							$manifests
							| del(.[].annotations["org.opencontainers.image.ref.name"])
						),
					},
				}
			end
		)
	)
	| .[] # strip off our synthetic map keys to avoid leaking our implementation detail
;

# input: array of "build" objects (with "buildId" top level keys)
# output: stream of input objects for "cmd/deploy" ({ "type": "manifest", "refs": [ ... ], "data": { ... } })
# cosignRepos: repositories to push :sha256-xxx.sig tags to, such as "oisupport/referrers"
# pushByDigestRepos: repositories to push @sha256:xxx manifests to (OCI referrers API lookup only), such as "arm64v8/hello-world" ([ .source.arches[.build.arch].archTags[] | split(":")[0] ])
def deploy_signatures(cosignRepos; pushByDigestRepos):
	.[]
	| select(.build.resolved)
	| . as $build
	# TODO strip any tags off these values here instead of having the invoker do that (so this can just be an indiscriminte list of refs that we munge as appropriate) -- then we can handle the stripping in a way that's more careful about the colons in digests and port numbers 😂
	| ([ cosignRepos ] | flatten | unique) as $cosignRepos
	| ([ pushByDigestRepos ] | flatten | unique) as $pushByDigestRepos
	| .build.prodSignatures[]?
	| .annotations["vnd.docker.reference.digest"] as $subjectDigest
	| {
		type: "manifest",
		refs: [
			"\($cosignRepos[]):\($subjectDigest | gsub(":"; "-")).sig",
			$pushByDigestRepos[],
			empty
		],
		lookup: { (.digest): $build.build.img },
		data: {
			# TODO this is replicating a lot of stuff from "sign-image.sh" that should be factored out into a shared file
			schemaVersion: 2,
			mediaType: media_type_oci_image,
			artifactType: media_type_cosign_artifact,
			subject: first($build.build.resolved.manifests[] | select(.digest == $subjectDigest)),
			layers: [ . ], # TODO this is missing the "data" field because we didn't include it in the JSON (there's a matching TODO over in "./cmd/builds") -- something to ponder for the future
			# TODO if we ever end up with multiple *different* signatures for the same $subjectDigest, that's not a thing that Tianon is aware of cosign having any support for, but it would be pretty reasonable to make them multiple layers in the same manifest (since it doesn't support indexes AFAIK and those would be harder for us to generate here anyways)
			config: oci_empty_descriptor,
		},
	}
;
