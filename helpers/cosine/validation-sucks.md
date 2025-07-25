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
  - https://kyverno.io/docs/policy-types/cluster-policy/validate/ is pretty great, and lets us drill down into the object and perform registry lookups at whatever point we need, great
  - HOWEVER, https://main.kyverno.io/docs/policy-types/cluster-policy/verify-images/sigstore/ is how you hook into the cosign apparatus, which is impressively well-fleshed-out, but `verifyImages:` is totally exclusive/orthogonal to `validate:` so they cannot be combined and we're back to bunk 🤬
  - for posterity, the saved playground from my "learning Kyverno" session from before I got completely blocked and depressed again: https://playground.kyverno.io/#/?content=N4IgDg9gNglgxgTxALhAQzDAagUwE4DOMEAdsgAQDWCAbviRAHTED0NAjADomUwkAmFAMJQArgQAu%2BAArR4CbgFscEtPzSrk3cuRJplFHAA99YKDgC0/CDAuRYibgTA44WkjryjzBdzou6%2BjgUeDgAjqIwoRYARmgEljCKaADmONo65MkScAAWfpk6aCQIBYUBoQQQonhwOL4ZhYW8Ag0eTeXksvyNHeQQLngaxCRtfZkBQgBKAKIAggAqM70dAQCq0gAii8vtOjRosOpSZZnKBASpweScIACSyWkEWeIS5M6uMABmCORo79VajgWHEEuQkldyF88BBFOQAO65eC5cgSXI4X5oULkGKRKASRi3FZQiChNB5U7%2BciwSQUW4AbXIoQi9QJEBiACtXASPnBGHBSKo%2BPgCAAaJnhUSsxjsrlwHkuPl8GASISCtDCwji5lSyQyzncxi8xg4MDo5RDKBqkhCkgi8gAXXpDqJeyaAptxgkdLdnT0BnBjxwmw0aGJhQhaSmOBSMEkeFKN19fVCX3wOBIdTpIGAwHIOHMyhtzCD5AAvmXXeMAv7rop2QgqjU6uHMgc8DA0DFzJS%2BhzztINPlA1cQ6p%2BaQvjAUmO0ISQPWYghGLiYFB%2BLwCav13wvkwOLdyAAfHHxHAANgALAB9fiuCB3gAUAAEAJSMMBYhLXjlVEgv19jwBZt6npAB%2BCQEBccgAF4YPIAByaw4EofALEjHAEIdRhUyA8wSBSNEANbQo7y%2BNBvG9cgAAZWxrIIKAgOA40BOooC7AsCBI8h207btgm4nR%2B3qQc0QoDDZwnEgpxnUMpJkxgABkOKgZ4T1QxtiOTDoyIo/EKGdOjAgDJiWJA4oGFUCQRi47S2yxPie0E8hhIIUThwkuTkhIb5pQsiArJs%2BdSRSGUXEzdVNQIEsrhXM9GFrKtxkyXTKIoBCEKM2sKG3fhPxQ2zkp4hyuycuzClc9yKE/QgcB/P9H088cPRkySWunJSVOi25iBXPE8vJShotgNNEDgcxGGUVRjjDEB3y8EgHli1N00zHBjxPGrv1/UhGqDNrJ2nA7pI65SYk4%2Bdety/KhsYEbXAQcacEmlQ1FDW530kQacNERagxitJnNS/TEMyuy7xKXtCg9fgVRsqGmkOKAEdWKgMWzEKwozD1bRFAHntBZ7EpAZzCgGfANFJCg5hKAA5AK7hIUn7LEa5blzfpmKbIF2PO1SKySoqqQ07MOdM7m6n8wLSAIAWSfKvpyaGCQqfIGYIkOQqhcKA5WfSsHteF9GbhzPNF0bVj1rl5mdCVym8AodXRE1m3ir1mjmYCEWTY567Buea2FY6O2VYdtWNdU13dalfXuBAUUQEqS2UBACw0%2B4DBsBFEYKAPHg%2BEELoHyUV6ZoKbKsgQOxi9GRUChxjU7UIU4AgwihrOKUgWDtCR4VJSgLBV6AYggIxkDvGJOyZ5MK7gLg3VboN26nruJC8YJTOJWeACZekXq5l87kgWEUeAYSqL4JAsHB%2BDSZAvv4reGPIOAAGY95HO/wUIIgn4DOBLwZGVKqSKTcxgTE/tcdEUAoAQAsH3PA64/7XGAfPTobdUQr2PikCABBRDIPEj5CQu92imnNBTK0oCRQt0gYfBgx8CDmFNHwFIsQcAUUggQ/MZp57cDThYbgABicguQJASDAL4FgLBqB0DwAwZgEAWDIQICwew8hB5QXqCwcarw0JqMQCwDhEA0jHwzpgXAhAc5/DABItg88WiFxDDgesJAADKKgS7TVDOXZ%2Bigq7qGcTLDxtdXAFASOYeUqtgCVnaFIRQZgNACTdLyXsDcooI33l/Du9Du4qAQQPIeUAR5j0OJgO03FZ5oL6Jk642TV7r2QAgaAm8FY7yMhgupx9T5wHPhAS%2B19b7BHOqoCpz837xxANAfg0YJY4BThMuArxYQzMtpsHAU4iE2XmQnHRkh8ArJAgQbZIBjB1DANZGW8yyxAA
