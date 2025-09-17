# a helper for "build_should_sbom"
def _sbom_subset:
	[
		# only repositories we have explicitly verified
		"aerospike",
		"almalinux",
		"alpine",
		"alt",
		"amazoncorretto",
		"amazonlinux",
		"api-firewall",
		"arangodb",
		"archlinux",
		"backdrop",
		"bash",
		"bonita",
		"buildpack-deps",
		"busybox",
		"caddy",
		"cassandra",
		"chronograf",
		"cirros",
		"clojure",
		"composer",
		"convertigo",
		"couchdb",
		"crate",
		"debian",
		"drupal",
		"eclipse-mosquitto",
		"eclipse-temurin",
		"eggdrop",
		"elasticsearch",
		"elixir",
		"emqx",
		"erlang",
		"fedora",
		"flink",
		"fluentd",
		"gazebo",
		"gcc",
		"geonetwork",
		"ghost",
		"golang",
		"gradle",
		"groovy",
		"haproxy",
		"haskell",
		"hitch",
		"httpd",
		"hylang",
		"ibm-semeru-runtimes",
		"ibmjava",
		"influxdb",
		"irssi",
		"jetty",
		"jruby",
		"julia",
		"kapacitor",
		"kibana",
		"kong",
		"liquibase",
		"logstash",
		"mageia",
		"mariadb",
		"maven",
		"memcached",
		"mongo",
		"mongo-express",
		"mono",
		"mysql",
		"neo4j",
		"neurodebian",
		"nginx",
		"node",
		"odoo",
		"openjdk",
		"open-liberty",
		"oraclelinux",
		"orientdb",
		"perl",
		"photon",
		"php",
		"plone",
		"postgres",
		"pypy",
		"python",
		"r-base",
		"rabbitmq",
		"rakudo-star",
		"redis",
		"registry",
		"rethinkdb",
		"rockylinux",
		"ros",
		"ruby",
		"rust",
		"sapmachine",
		"satosa",
		"silverpeas",
		"solr",
		"sonarqube",
		"spark",
		"spiped",
		"storm",
		"swift",
		"swipl",
		"telegraf",
		"tomcat",
		"tomee",
		"traefik",
		"ubuntu",
		"websphere-liberty",
		"wordpress",
		"xwiki",
		"znc",
		"zookeeper",

		# TODO: add these when PHP extensions and PECL packages are supported in Syft
		# "friendica",
		# "joomla",
		# "matomo",
		# "mediawiki",
		# "monica",
		# "nextcloud",
		# "phpmyadmin",
		# "postfixadmin",
		# "yourls",

		# TODO: add these when the golang dependencies are fixed
		# "nats",
		# "couchbase",

		# TODO: add these when sbom scanning issues fixed
		# "dart",
		# "clearlinux",
		# "rocket.chat",
		# "teamspeak",
		# "varnish",

		empty
	]
;

# https://github.com/docker-library/meta-scripts/pull/61 (for lack of better documentation for setting this in buildkit)
# https://slsa.dev/provenance/v0.2#builder.id
def buildkit_provenance_builder_id:
	"https://github.com/docker-library"
;

# input: "build" object (with "buildId" top level key)
# output: boolean
def build_should_sbom:
	# see "bashbrew remote arches docker/scout-sbom-indexer:1" (we need the SBOM scanner to be runnable on the host architecture)
	# bashbrew remote arches --json docker/scout-sbom-indexer:1 | jq '.arches | keys_unsorted' --compact-output
	(
		.build.arch as $arch | ["amd64","arm32v5","arm32v7","arm64v8","i386","ppc64le","riscv64","s390x"] | index($arch)
	) and (
		.source.arches[.build.arch].tags
		| map(split(":")[0])
		| unique
		| _sbom_subset as $subset
		| any(.[];
			. as $i
			| $subset
			| index($i)
		)
	)
;

# input: "build" object (with "buildId" top level key)
# output: key-value of (architecture trust-boundary specific) public keys (in PEM format) that should be used to verify the validity of a given build (labelled with a superfluous name for our sake / to be embedded in "builds.json" so it's easier to identify which images are signed by a given key, especially during rotation periods)
# - might (likely) have extraneous whitespace that should be trimmed/ignored for valid PEM parsing
# - empty object or empty string means "no signature" should be considered valid
def build_arch_sign_public_keys:
	# TODO if normalized_builder is classic, we can't currently sign those builds (but normalized_builder is defined in meta.jq so we'd have to pull that out to use it here, which is sane but ENAMING)
	{
		"mips64le": {
			"mips64le (primary) yubi 31992878 9c": "
				-----BEGIN PUBLIC KEY-----
				MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdAxMzxIpv1AMbzE+ycjyq4/VxQKh
				po/toKqH2ULTNVr41ktEcyuvHxT/gNfjHLRe79XTB06UTDLYqOGvfI35vA==
				-----END PUBLIC KEY-----
			",
			#"mips64le (backup) yubi 31992760 9c": "
			#	-----BEGIN PUBLIC KEY-----
			#	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXmNFPvf/vpmOpZd0IyONAbJA0nPz
			#	wOR7i95matoQC4OO2PkCkQ0zUV5WvsikTlZR6dILsdS+KehYbWfRO07qfw==
			#	-----END PUBLIC KEY-----
			#",
		},
		"riscv64": {
			"riscv64 (primary) yubi 31992931 9c": "
				-----BEGIN PUBLIC KEY-----
				MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/3vIKIZs1mhnrthNpEqC9SBmnFFJ
				CvEj8WWPvXB1R9xX03/MmAg8QU4FD9dnFXr+zdkJ3RqLEXovxzO03KoK9Q==
				-----END PUBLIC KEY-----
			",
			#"riscv64 (backup) yubi 31992898 9c": "
			#	-----BEGIN PUBLIC KEY-----
			#	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYCVWz7ZwW5Lu8+U2OkPS1AnBOGmo
			#	F/Desit+a0xXCMdDEew0rUE1cJcTZyeZuGRGE8H4KeT6Z1UfQ/OqDJUX3w==
			#	-----END PUBLIC KEY-----
			#",
		},
	}[.build.arch]
	// {}
;

# input: "build" object (with "buildId" top level key)
# output: boolean
def build_should_sign:
	(env.BASHBREW_META_SCRIPTS_RUNNING_TESTS == "vigorously") # for the tests
	or (build_arch_sign_public_keys | length > 0)
;
