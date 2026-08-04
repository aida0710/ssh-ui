# API Contract Generation

`openapi.yaml` intentionally uses OpenAPI 3.1, while the pinned
`oapi-codegen v2.7.0` does not fully support OpenAPI 3.1. This boundary is
intentional: the current contract uses only the validated basic subset of
object, string, const, required, reference, response, and header constructs.
The generator's upstream compatibility note is tracked at
https://github.com/oapi-codegen/oapi-codegen/issues/373.

Generate and verify the contract with:

```sh
go generate ./internal/api
npm run generate:api --prefix web
go test ./internal/api -count=1
npm run typecheck --prefix web
```

Before adding an OpenAPI 3.1-only feature, validate generator compatibility or
introduce an overlay that keeps the generated input within the supported
subset.

## Generated naming convention

oapi-codegen v2.7.0 renders a camelCase property as Go PascalCase with only the
first letter capitalised, so `id` becomes `Id`, `keyId` becomes `KeyId` and
`transactionId` becomes `TransactionId` — not `ID`. Match the generator in
hand-written code rather than editing `models.gen.go`, which is regenerated.
A property that is not in `required` becomes a pointer with `omitempty`, which
is why `Problem.Detail` is a `*string` and `KeyItem.Certificate` is a
`*KeyCertificate`.

## Key vault contract decisions

- Timestamps are plain `type: string` values in RFC 3339 form, not
  `format: date-time`. The generator's 3.1 support is validated only for the
  basic subset, and a plain string keeps both generated languages predictable.
- Value sets such as `kind`, `algorithm` and the action `kind` are plain strings
  rather than `enum`, and are validated at runtime in Go at the API boundary.
  Type generation is never the only check on an input.
- `Problem.detail` carries a bounded, home-sanitised message such as `ssh-add`
  stderr. It must never contain key material, a passphrase, a token or an
  absolute path.
- `KeyCertificate.validBefore` is a signed integer plus a `neverExpires` flag.
  OpenSSH spells "never expires" as 2^64-1, which does not fit a signed integer,
  so that case is reported as `neverExpires: true` with a zero bound instead of
  being wrapped into a negative number.
- `POST /api/v1/keys/hardware-command` changes nothing on disk. It is a POST so
  it carries a validated JSON body and is covered by the CSRF requirement like
  every other non-GET request.
- `IssueActionRequest` carries only `kind` and `target`, never the evidence the
  token is bound to. The server derives the evidence from what the confirmation
  dialog was showing — a private key's path, fingerprint and content digest, or
  a trash entry's listed contents — at both issue and consume time. A caller
  that could supply its own evidence could bind a token to a state that was
  never displayed, which is exactly what the binding exists to prevent.
- The action `kind` values are the shared `internal/session` constants
  `private_key.reveal` and `trash.purge`. They are spelled `domain.verb` because
  the session package owns the vocabulary for every subsystem that confirms an
  operation.
