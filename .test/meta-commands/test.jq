include "meta";
include "doi"; # TODO remove this
[
	first(.[] | select(normalized_builder == "buildkit")),
	first(.[] | select(normalized_builder == "classic")),
	first(.[] | select(normalized_builder == "oci-import")),
	first(.[] | select(normalized_builder == "oci-import" and build_should_sbom)), # TODO remove this
	empty
]
| map(
	. as $b
	| commands
	| to_entries
	| map("# <\(.key)>\n\(.value)\n# </\(.key)>")
	| "# \($b.source.arches[$b.build.arch].tags[0]) [\($b.build.arch)]\n" + join("\n")
)
| join("\n\n")
