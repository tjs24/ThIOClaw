"""
telemetry/
----------
Source-agnostic telemetry ingest for the Data Plane.

Every collector format is normalized into the NormalizedEvent schema
(schema.py) before Tier 1 scoring, so the scoring layer never sees a raw
collector shape. Adapters live in telemetry/sources/ (one per collector);
two adapters make the seam real rather than asserted. See CONTEXT.md.
"""
