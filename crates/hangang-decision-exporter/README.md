# Hangang Decision Exporter

[한국어](README.ko.md) · [Hangang](../../README.md) · [Guide](../../docs/DECISION_EVENTS.md)

Independent `hangang-decision-exporter` process (ADR 0019). It receives
`hangang.decision.v1` batches from Hangang over a `0600` Unix socket, validates
every event, stores them in SQLite (WAL) with `event_id` uniqueness and enforces
age and byte caps by dropping whole hourly partitions (default 7 days and 2 GiB,
hard maximum 90 days). A separate read-only Unix socket serves the decision
list, facets, time series, request detail, status and Prometheus metrics to the
Hangang management broker.

The exporter has no policy credential and no pseudonymization key. Ingest is
bounded by connection count, frame size, an idle timeout and a writer queue;
queries are bounded to 200 rows, a 31-day window and a 3 second deadline.

```sh
hangang-decision-exporter --ingest-socket /run/hangang/decision-ingest.sock \
  --query-socket /run/hangang/decision-query.sock --store /var/lib/hangang/decisions.db
```
