# Blockers

- documentation (especially validation: `helpers/cosine/kyverno-policy.yml`), blog post?
  - `helpers/cosine/notes.md` but more focused and having learned from the actual implementation, where that details more of what my plan was, which is close but not 100%

- referrers deploy (see TODO in `Jenkinsfile.deploy`)

- `git rm -r helpers/cosine` (moving/rewriting any useful notes or scripts somewhere more persistent)

- more testing with actual AWS KMS

- a bucketload of Terraform

# Probably Important

- better error handling around "bad signatures" (see TODOs in `cmd/builds` where we panic for any funny business and a lot of that should be considered BADSIG instead and be ignored)
  - see also `registry/cosign.go` where we'll need to annotate/wrap errors better to accomplish this reasonably (so that we can ignore invalid signatures as bad, but actually continue to error/fail on things like registry lookup errors)

- better logging in `cmds/builds`, especially around BADSIG cases

- more of the signing code in a library / with better testing (especially unit tests)
  - the Go code is somewhat straightforward
  - the Bash might need something like a unit test implementation in `helpers/sign-digest.sh` that can run deterministically and "fake" the signatures, possibly with an extremely limited set of digests so that code can't possibly get triggered in production without causing obvious errors/failure

- pull `normalized_builder` out of `meta.jq` so it can be used in `build_should_sign` and `build_arch_sign_public_keys` inside `system-config.jq` without creating an import cycle

- file issue(s) with Kyverno with Tianon's v1alpha1 policy writing product feedback (see `helpers/cosine/kyverno-policy.yml`)

- re-evaluate fields included in the payloads created in `helpers/sign-image.sh` (especially those under `optional:`)

# Nice To Haves

- ability to control what specific objects to sign via `system-config.jq` instead of embedding that directly in the Go (see TODOs in `cmd/builds`)

- cleaner "ref parsing" in `deploy.jq`'s `deploy_signatures`

- deduplicate/DRY `deploy.jq` and `helpers/sign-image.sh` manifest structure overlap

- pull `normalize_ref_to_docker` out of `meta.jq` so it can be used in `helpers/sign-image.sh`

- handle multiple signatures of the same object cleanly (and test whether `cosign` handles that in any sane way - multiple signature objects inside `layers` for example; see TODO in `deploy.jq`)

# Possible Futures

- self-generated provenance (SLSA? 🙃) + decide what to do with BuildKit's (especially since we will *not* be signing SBOMs)

- actual OCI referrers (pending Docker Hub enablement, obviously)
  - we've already structured the objects so this is ~easy (they have an appropriate `subject`), but they'll need to be pushed-by-digest to `library/` and the arch-specific namespaces for this to work, which is also ~easy but not worth doing unless/until Hub enables referrers

- enforcing ordering for signature upload (ie, signature *must* be uploaded and available for lookup before we push the relevant manifests to production repositories like the arch-specific namespaces or `library/`)

- upstream signatures?  `oci-import` is the only place this makes sense, and the benefits are dubious (we wouldn't reproduce that upstream signature as-is *unless* the testing mentioned above allows multiple signatures sanely)

- sign "classic" builds / Windows images too (unfortunately probably requires something like https://github.com/tianon/docker-bin/blob/aef2b35350eabe4748dddda3ccc0ddf02ad1526e/docker-save-oci-layout.sh which is more expensive the bigger images get, like the huge Windows ones 😞)
