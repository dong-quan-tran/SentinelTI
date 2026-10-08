# Supplemental URL records ? v1

This contract describes reviewed supplemental records. It does not authorize
model promotion, establish label correctness, or modify training inputs.

## Required CSV columns

- `url`: Original observed HTTP(S) URL. Do not add www, upgrade the scheme,
  or manufacture variants and inherit their labels.
- `label`: Exactly `benign` or `malicious`.
- `source`: Name of the dataset, collection process, or observation source.
- `source_reference`: Traceable source record ID, archived reference, or URL.
  This is not restricted to an HTTP link.
- `collected_at`: ISO timestamp with a timezone.
- `reviewed_at`: ISO timestamp with a timezone, at or after collection.
- `reviewer`: Stable reviewer identifier; avoid unnecessary personal details.
- `review_evidence`: Specific basis for the label and relevant limitations.
  Popularity, HTTPS, or absence from one threat feed alone is not sufficient
  evidence under this project policy.

All fields are required, nonempty, and free of surrounding whitespace.
Do not put credentials, API keys, or sensitive investigation details in records.

## Validation scope

The validator checks schema, basic URL parsing, supported labels, timestamp
ordering, exact duplicate URLs, and conflicting labels for identical URLs.
It performs no network requests and cannot verify the truth of review evidence.

It does not yet detect conflicts introduced by candidate normalization, compare
against the original training dataset, or assign train/evaluation partitions.
Those checks must occur before these records can enter candidate training.

## Evaluation policy

Reserve independent evaluation coverage rather than using every reviewed record
for training. Keep domain groups separated, report subgroup sample counts,
false-positive rates and malicious recall, and agree on acceptance criteria
before selecting a candidate.

The header-only template contains no actual training examples.
