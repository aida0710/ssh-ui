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
