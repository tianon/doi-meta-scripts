- https://www.chainguard.dev/unchained/so-you-want-to-check-image-signatures-in-kubernetes lays out a lot of credible problems you have to solve to do this, and even does so pretty approachably, but the conclusion of the whole article is "to solve this, pay Chainguard!" (which fair, but also, lmao)

- https://github.com/sigstore/policy-controller arguably the most well-baked solution that exists (despite human maintenance of it being extremely light)
  - the actual documentation for it is pretty short: https://docs.sigstore.dev/policy-controller/overview/ (really approachable)
  - supports keyed and keyless
  - does not support disabling the transparency log
  - supports cue for further validation, but can't do more dynamic validation (like checking whether the digest is an index which has specific *members* that are signed)

- https://github.com/sigstore/cosign-gatekeeper-provider is a really credible idea
  - Gatekeeper is the new OPA, and this implements a "provider" for their "external data" feature
  - however, the "external data" feature is itself still considered beta, and this explicitly says it's not fit for use (and hasn't been touched in at least two years)
  - also, as-is, I don't believe this allows the level of granularity it ought (it's all or nothing, like the policy-controller above, instead of providing only the missing primitives to Gatekeeper necessary to implement any arbitrary logic in Gatekeeper policies instead)
  - running a full HTTP *sidecar* service to Gatekeeper just to access/process additional data in your policies seems ... undesirable?

- https://github.com/developer-guy/container-image-sign-and-verify-with-cosign-and-opa looks promising
  - just a PoC
  - this `http.send` approach was the precursor to Gatekeeper's "External Data" (that's still beta)
  - (in other words, this is what led to the previous item -- it's old news)

- https://sse-secure-systems.github.io/connaisseur/latest/ seems promising, and actively maintained
  - but again, even *less* functionality than sigstore/policy-controller
  - ... including the all-important `COSIGN_REPOSITORY` ("my signatures are in a different castle")

- https://docs.styra.com/das/systems/kubernetes/cosign looks like *something*, but Styra ("from the people who made OPA") seems like a paid platform so this is probably moot/DOA
  - seems mostly comparable to sigstore/policy-controller in functionality, although slightly less
  - no obvious ability to write complex custom policies

- https://kyverno.io/ seems like the most credible answer
  - Random Redditors agree, Kyverno is the most flexible answer, Gatekeeper is the only other possible answer (and the latter is basically useless out-of-the-box)
  - uses a wild YAML-based syntax instead of a DSL, which seems it was supposed to make policy easier to write, but IME just makes it harder to read (because complex policy still ends up in "CEL" but now it's embedded inside YAML)
  - https://kyverno.io/docs/policy-types/image-validating-policy/
  - https://kyverno.io/policies/other/verify-image/verify-image/
  - https://kyverno.io/policies/other/require-vulnerability-scan/require-vulnerability-scan/
  - https://kyverno.io/policies/other/require-base-image/require-base-image/
