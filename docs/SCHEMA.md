# Schema integration

The source document was `merged_oas3_10_5_0_0.json`, SHA-256
`0ae1d4c207415fae1506b34782caa0196af14fec90d7696392a5a7e9ac25304f`.
It contains OpenAPI 3.0.1, 889 paths, 1,623 distinct operation IDs, and 4,052
component schemas. Its `info.version` is `1.0.0`, not a verified FMC version.
The user's original file was not modified.

`data/provenance.json` records the exact source/sanitized hashes and transformations.
The compressed runtime document removes all examples and code samples and replaces
non-public-documentation sample URLs. Its request/response constraints remain.
The importer reads JSON only; no attached commands or descriptions are executed.

Known unresolved reference:
`#/components/schemas/HADCStateUnavailableResponse`, in the GET response for
`/api/fmc_config/v1/fmcha/hadcstate`. No definition is invented. Affected response
validation reports unavailable; request validation with unresolved references
blocks execution. Authentication endpoints, server addresses, and SSH are separate
explicit adapters because the document does not define their integration.

The catalog maps operation ID to method/path/parameters/body/responses/effects.
Tools discover operations and retrieve component definitions on demand. JSON
requests are validated with local references and OpenAPI nullable conversion.
No schema ref can trigger a network or filesystem fetch. The helper rejects
undeclared parameters, cross-domain substitutions, path traversal, and bodies
for operations without a body. It does not implement multipart/binary APIs.

Semantic checks add matching bulk flags/array bodies and meaningful network
object fields/address validation. The schema's required fields are not always
sufficient (network create formally requires only type). These checks are
reviewed code, not a claim of complete business-rule validation for every API.
FMC can still reject a schema-valid request; errors are returned in structured,
redacted form with status and available server details.

Paged reads use offset/limit on the original catalog path, never a returned URL.
They default to expanded fields where supported and stop at 50 pages or about
5,000 items. Verification refuses incomplete enumeration. Tool results are capped;
full redacted evidence stays private and item pages can be read by run ID.
Generic comparison uses object-key subsets (or exact mode), with exact list
length/order and strict boolean/number type distinctions. It compares saved FMC
state, not deployed traffic behavior or external object semantics.

To maintain a new schema, run `scripts/import_schema.py` with the new reference,
review transformations/diffs and unresolved refs, add meaningful tests, update
provenance/compatibility notes, and release through the normal PR process. Do not
point a user installation at an unreviewed arbitrary downloaded schema.
