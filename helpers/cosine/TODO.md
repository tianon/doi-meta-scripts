# Blockers

- documentation (especially validation: `helpers/cosine/kyverno-policy.yml`), blog post?
  - `helpers/cosine/notes.md` but more focused and having learned from the actual implementation, where that details more of what my plan was, which is close but not 100%

- dedicated referrers repo deploy (see TODO in `Jenkinsfile.deploy`)

- `git rm -r helpers/cosine` (moving/rewriting any useful notes or scripts somewhere more persistent)

- more testing with actual AWS KMS
  - confidence is high, so maybe this exhibits as just enabling it for arm32 to start with 🤷

- a ~~bucketload~~ thimble of Terraform (and a pretzel of AWS IAM / policy)

# Probably Important

- better error handling around "bad signatures" (see TODOs in `cmd/builds` where we panic for any funny business and a lot of that should be considered BADSIG instead and be ignored)
  - see also `registry/cosign.go` where we'll need to annotate/wrap errors better to accomplish this reasonably (so that we can ignore invalid signatures as bad, but actually continue to error/fail on things like registry lookup errors)

- better logging in `cmds/builds`, especially around BADSIG cases

- pull `normalized_builder` out of `meta.jq` so it can be used in `build_should_sign` and `build_arch_sign_public_keys` inside `system-config.jq` without creating an import cycle

- ~~file issue(s) with Kyverno with Tianon's v1alpha1 policy writing product feedback (see `helpers/cosine/kyverno-policy.yml`)~~
  - https://github.com/kyverno/kyverno/discussions/14036

- re-evaluate fields included in the payloads created in `helpers/sign-image.sh` (especially those under `optional:`)

- re-evaluate how we store the signing data in the Git repo, as `builds.json` is already getting huge *and* we might get forced to sign in different (worse) ways in the future

- choose a better `creator` value (see TODO in `helpers/sign-image.sh`)

# Nice To Haves

- ability to control what specific objects to sign via `system-config.jq` instead of embedding that directly in the Go (see TODOs in `cmd/builds`)

- cleaner "ref parsing" in `deploy.jq`'s `deploy_signatures`

- deduplicate/DRY `deploy.jq` and `helpers/sign-image.sh` manifest structure overlap

- pull `normalize_ref_to_docker` out of `meta.jq` so it can be used in `helpers/sign-image.sh`

- handle multiple signatures of the same object cleanly (and test whether `cosign` handles that in any sane way - multiple signature objects inside `layers` for example; see TODO in `deploy.jq`)

- more of the signing code in a library / with better testing (especially unit tests)
  - ~~the Go code is somewhat straightforward~~
  - ~~the Bash might need something like a unit test implementation in `helpers/sign-digest.sh` that can run deterministically and "fake" the signatures, possibly with an extremely limited set of digests so that code can't possibly get triggered in production without causing obvious errors/failure~~
  - we could probably do more here, but we're in a pretty OK state now (with good coverage)

# Possible Futures

- self-generated provenance (SLSA? 🙃) + decide what to do with BuildKit's (especially since we will *not* be signing SBOMs)

- actual OCI referrers ~~(pending Docker Hub enablement, obviously)~~
  - we've already structured the objects so this is ~easy (they have an appropriate `subject`), but they'll need to be pushed-by-digest to `library/` and the arch-specific namespaces for this to work, which is also ~easy ~~but not worth doing unless/until Hub enables referrers~~
  - ... in hindsight, this is actually *easier* than pushing to a dedicated "referrers" repository since our deploy pushing user already has push access to the arch-specific namespaces 🤔

- enforcing ordering for signature upload (ie, signature *must* be uploaded and available for lookup before we push the relevant manifests to production repositories like the arch-specific namespaces or `library/`)
  - this probably exhibits as updating "deploy" such that if it sees an object with a "subject" that it makes sure that is pushed successfully before allowing any pointer with that subject digest to consider pushing (this might be hard because the subject lives inside the index we're pushing and we need to block the index/child push), and making sure we list then in the appropriate order during deploy

- upstream signatures?  `oci-import` is the only place this makes sense, and the benefits are dubious (we wouldn't reproduce that upstream signature as-is *unless* the testing mentioned above allows multiple signatures sanely)

- sign "classic" builds / Windows images too (unfortunately probably requires something like https://github.com/tianon/docker-bin/blob/aef2b35350eabe4748dddda3ccc0ddf02ad1526e/docker-save-oci-layout.sh which is more expensive the bigger images get, like the huge Windows ones 😞)
  - maybe, someday, we can get the containerd integration and have some way to get an OCI bundle that *doesn't* include those base image layers?  but then we still need to push them somehow 🤔
  - (assuming containerd integration *and* support for it,) push-by-digest, then sign from the locally-generated digest, then push a tag?
