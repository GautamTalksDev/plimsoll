# PLIMSOLL generic harness result format

Version: **plimsoll-generic-v1**

The generic adapter lets any custom harness produce PLIMSOLL-compatible
result files without waiting for a first-party adapter. Adapters **map and
extract only**; they never compute aggregates such as means. Per-row metric
strings are carried in their **original JSON literal form** (never
round-tripped through `float64`).

## File shape

Top-level JSON object:

| Field | Required | Description |
|-------|----------|-------------|
| `format` | yes | Must be exactly `plimsoll-generic-v1`. |
| `harness_version` | yes | Semver string for *your* harness exporter (not PLIMSOLL). Supported range: **1.0.0 – 1.99.99**. |
| `rows` | yes | Non-empty array of row objects (see below). |
| *(any other key)* | no | Preserved verbatim in `ResultSet.Extra`. |

### Row object

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Stable row identifier string. Used only for `RowDigest`; never stored as row content. |
| `metrics` | yes | Object mapping metric id → JSON literal (string, number, boolean, or null). |
| *(any other key)* | no | Ignored by the adapter (not copied into PLIMSOLL storage). |

Metric ids should match the ids declared in your sealed preregistration
(`metrics[].id`). Aggregates named in the decision rule (e.g. `acc.mean`) are
computed later by the decision engine from these per-row values.

## Example

```json
{
  "format": "plimsoll-generic-v1",
  "harness_version": "1.0.0",
  "team": "research",
  "rows": [
    {
      "id": "split-train-00042",
      "metrics": {
        "acc": "1",
        "latency_ms": "38.5"
      },
      "note": "local-only metadata; not extracted"
    },
    {
      "id": "split-train-00043",
      "metrics": {
        "acc": "0",
        "latency_ms": "51"
      }
    }
  ]
}
```

After `adapt.Adapt("generic", raw)`:

- `Harness` = `"generic"`
- `HarnessVer` = `"1.0.0"`
- `Metrics["acc"].Raw` = `["1", "0"]` (original string forms, row order)
- `RowDigest` = `sha256:` digest over `split-train-00042` and
  `split-train-00043` only
- `Extra` = `{"team":"research"}` (unknown top-level keys, unmodified)

## Row digest

`RowDigest` is `sha256:` over the UTF-8 string:

```
plimsoll-row-digest-v1\n
<id-0>\n
<id-1>\n
...
```

Row ids appear in submission order. No prompts, outputs, or metric values
enter the digest.

## Version policy

If `harness_version` is outside **1.0.0 – 1.99.99**, adaptation returns
`ErrUnsupportedVersion`. PLIMSOLL does not guess across major exporter
versions.

## Detection

`adapt.Detect` selects the generic adapter when `format` equals
`plimsoll-generic-v1` (highest priority among adapters).

## Conformance checklist

- [ ] `format` is exactly `plimsoll-generic-v1`
- [ ] `harness_version` is semver in the supported range
- [ ] Every row has non-empty `id` and non-empty `metrics`
- [ ] Metric values are JSON literals (not pre-aggregated means unless that
      literal is what your harness reports per row)
- [ ] No aggregate-only export (compute per-row scores in your harness, or
      emit one row per evaluated unit)
