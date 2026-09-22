# HTTP response caching

[Documentation](README.md) · [한국어](ko/CACHE.md)

Hangang provides an opt-in shared response cache with bounded memory storage and optional SQLite persistence. Enable storage once at the top level, then enable freshness policy on each route that may be cached. Both settings are required.

```json
{
  "cache": {
    "memory": {
      "max_bytes": 8388608,
      "max_entries": 2000,
      "eviction": "lru"
    },
    "disk": {
      "directory": "/var/lib/hangang/cache/instance-a",
      "max_bytes": 67108864,
      "max_entries": 20000,
      "eviction": "lru"
    },
    "max_object_bytes": 262144,
    "max_fills": 16,
    "fill_timeout_ms": 3000,
    "generation": 0
  },
  "http": [
    {
      "id": "catalog",
      "path_prefix": "/catalog",
      "path_match": "exact",
      "cache": {
        "ttl_seconds": 30,
        "max_ttl_seconds": 120
      },
      "backends": ["http://127.0.0.1:8080"]
    }
  ],
  "tcp": []
}
```

The complete runnable configuration is [examples/cache/hangang.json](../examples/cache/hangang.json). Cache fields reject unknown properties, and invalid limits reject startup, file reload, API validation and API update. A rejected reload leaves the last valid snapshot active.

## Storage policy

| Setting | Default | Allowed values | Meaning |
| --- | ---: | ---: | --- |
| `memory.max_bytes` | 67,108,864 | `0..isize::MAX` | Weighted memory entry capacity; zero disables memory |
| `memory.max_entries` | 10,000 | `0..1,000,000` | Memory entry count; must be positive when memory is enabled |
| `memory.eviction` | `lru` | `lru`, `fifo` | Memory eviction order |
| `disk` | omitted | object or omitted | Optional persistent tier |
| `disk.max_bytes` | required | `65,536..8,796,093,018,112` | SQLite main-file plus rollback-journal budget |
| `disk.max_entries` | required | `1..1,000,000` | Disk entry count |
| `disk.eviction` | `lru` | `lru`, `fifo` | Disk eviction order |
| `max_object_bytes` | 1,048,576 | `1..16,777,216` | Maximum weighted size of one complete entry |
| `max_fills` | 32 | `1..1,024` | Concurrent response captures |
| `fill_timeout_ms` | 5,000 | `1..30,000` | Deadline for capturing a response body after its headers arrive |
| `generation` | 0 | `0..4,294,967,295` | Fleet-wide invalidation generation; every key is namespaced by it |

At least one storage tier must be enabled. Memory uses an indexed LRU or FIFO queue and bounds both entry count and weighted bytes. A hit returns a cheap clone of the stored `Bytes`; it does not copy the complete body. The weight includes the key, body, header names and values, per-header tuple storage, and a fixed 256-byte entry allowance.

`memory.max_bytes` is a cache accounting budget, not an RSS limit. Hash tables, ordering indexes, shared body allocations, active response captures, network buffers, SQLite, the allocator and the rest of the process consume additional memory. In particular, captures can hold up to `max_fills * max_object_bytes` bytes of response data outside the stored-entry LRU budget (32 MiB with defaults; up to 16 GiB at both allowed maxima), plus response metadata and transport buffers. Set these fields from a measured process-memory budget under expected concurrency.

Disk storage uses `cache-v1.db` inside the configured absolute directory. It bounds logical entry count and size, and caps the main database file through SQLite's 4,096-byte `max_page_count`. The database uses a `TRUNCATE` rollback journal so an interrupted transaction (for example an OOM kill) is rolled back on the next open instead of corrupting the file; the `-journal` sidecar temporarily holds the previous content of every page a transaction modifies. The page budget charges one complete journal record (the original 4,096-byte page plus its 8-byte record framing) for every main-file page and reserves 10% for journal headers and alignment. The main file therefore stays below half of `disk.max_bytes`, and the modeled main-file-plus-journal peak stays within the configured bytes even for purge transactions that modify every page. A database created by an earlier build may exceed this journal-safe main-file allowance; Hangang rejects it before modifying it, and the operator must remove the rebuildable `cache-v1.db` before reopening the cache. `GET /v1/cache` reports both the main file and journal as `disk_bytes` and `disk_journal_bytes`. An insert that reaches the physical cap evicts and retries; an object that cannot fit even an emptied database is bypassed and counted, and any other storage failure fails open: the client still receives the origin response, the memory copy remains available when memory is enabled, and the storage error counter increases.

Use a dedicated cache directory for each running Hangang instance, including replicas that share the same main configuration. The directory must be absolute, contain no symlink component, and either not exist or already be a private `0700` directory. Hangang creates its database as `0600`, rejects symlink files and refuses a database without its application identifier. It never overwrites an unrelated file. The process takes a nonblocking exclusive ownership lock for the store's lifetime. Linux locks the database file; macOS uses a separate private `0600` file, `cache-v1.db.owner-lock`, to avoid interfering with SQLite's database locks. Keep that sidecar in place while a store is running; removing or replacing it can split ownership between different file identities. The empty sidecar contains no cache entries. See [SQLite's locking styles](https://www.sqlite.org/compile.html#enable_locking_style) for the platform-dependent database-locking behavior.

Memory in front of disk is the recommended general configuration. A memory miss tries the single disk I/O gate without waiting; concurrent disk access bypasses to the origin. Disk-only mode provides capacity and restart persistence, but contention can bypass it and it is not a promised latency improvement over a nearby origin.

An unchanged top-level cache policy reuses the same store across configuration reloads, and so does a change of `generation` alone (see below). Changing any other top-level cache field creates a fresh memory store immediately. An older in-flight configuration snapshot can retain the database lock until its requests drain, so the new store can temporarily bypass disk (each attempt counts a storage error and is retried on the next access). When it can open the database, it compares a fingerprint of the full cache policy and of the key derivation. A changed policy clears entries and runs `VACUUM` before applying the new physical quota. This prevents data retained under an old capacity or eviction policy from being served after a policy change.

## Invalidation generation

`cache.generation` is an integer in the shared configuration document. Every cache key is namespaced by it, and a running gateway that activates a document with a higher value discards both storage tiers at activation (never while a change is merely being prepared, so a rejected write leaves the live cache untouched) without rebuilding the runtime, so an in-flight fill or lookup that began under the previous value can neither be served nor published. Because it travels with the configuration, one update reaches every instance that shares the document, and the update is auditable like any other: it produces a new `revision` and `ETag`.

- In shared-store modes `POST /v1/cache/purge` performs a fleet purge by committing the same document with the next generation (compare-and-swap). Each instance applies it on its next poll; until then that instance still serves its entries.
- In file mode the endpoint purges only the instance that received it, as before. Edit `generation` in the file to invalidate every instance that reloads it.
- The value is monotonic: a running gateway adopts only a higher generation, and the document carries `cache_generation_floor` (the highest generation ever committed, kept even while `cache` is null); an API write that would lower `generation` — a whole-document rollback, or re-enabling the cache with the default 0 — is stored raised to that floor on every instance, so a purge that happened in between stays effective and a later purge cannot be skipped. At 4,294,967,295 a purge is refused (422) until the field is reset with a cache policy change; the value never wraps. Omitting the field means 0.
- The generation is recorded in the disk database. On open, rows of any other generation are deleted, so a purge interrupted by a crash, or one that landed while the database was not yet open, is completed on the next open; rows of the current generation survive restarts.
- Editing a route moves its entries to another key namespace, and reverting the edit restores the previous namespace together with its still-fresh entries. That is not an invalidation; use the purge endpoint (or the generation) when the old representations must not come back.

## Route freshness

`ttl_seconds` defaults to 30 and `max_ttl_seconds` defaults to 300. They must satisfy:

```text
1 <= ttl_seconds <= max_ttl_seconds <= 86400
```

Only complete `200 OK` responses are admitted. `s-maxage` takes precedence over `max-age`; either is capped by the route maximum. If neither is present, Hangang uses `Expires` relative to `Date`, then the route default. It accounts for upstream `Age`, apparent age from `Date`, and time spent receiving response headers. An entry expires at its stored time plus its remaining lifetime. Cache hits replace framing as needed and set `Age` to the accumulated age.

Response caching is deliberately conservative. Hangang bypasses responses with `Set-Cookie`, `Content-Range`, trailers, SSE, duplicate or malformed Content-Type, invalid or wildcard `Vary`, malformed or duplicate freshness metadata, or `no-store`, `private` or `no-cache`. Unknown Cache-Control extensions also bypass because their semantics may affect shared storage. A native buffered response transform may be cached after transformation; Lua and streaming response transforms make the route ineligible.

Routes using external authorization, route Lua, JSON request matching, or request transformation are ineligible. Requests must be empty-body GETs. Any Cache-Control or Pragma request directive bypasses ordinary caching; `only-if-cached` currently receives `504` without an origin request. Authorization, Proxy-Authorization, Cookie, Range, Content-Range, Upgrade and every `If-*` header also bypass.

Keys are SHA-256 hashes and do not expose request header values or URI data in the database key column. A key covers the original admitted request method, URI scheme/authority/path/query, TLS state, client peer-IP partition, the full route fingerprint, the invalidation generation, and all original end-to-end request headers before proxy forwarding headers and body transforms are applied. Header names are sorted and repeated values retain their order. Hop-by-hop fields are excluded, and requests with more than 64 KiB of key header material bypass. The broad key keeps representations separated at the cost of fewer hits. Cached status, headers and body are stored in SQLite without encryption; protect the directory and use encrypted storage when data-at-rest encryption is required.

## Fill, failure and purge behavior

A miss captures the response while forwarding it. Hangang publishes only after a complete body reaches EOF or a final body frame verifies end-of-stream; body error, client cancellation, trailers, capture timeout or weighted object overflow abandons the fill without storing a partial response. At most `max_fills` captures are active. Same-key followers wait up to 250 ms for the current fill, then bypass if no entry appeared; unrelated excess fills bypass immediately.

Storage failures do not fail an otherwise valid proxy request. Disk reads and writes use nonblocking admission and may bypass during contention. Memory hits avoid disk work. Purge is different: it clears memory and waits for exclusive disk access, returning an error if persistent deletion fails. The runtime advances a local epoch while holding publication control, so a fill that began before purge cannot repopulate the cleared store. The local epoch is not part of the stored keys (it restarts with the process, and keying by it would strand every entry written after a purge across a restart); the configuration generation is.

The authenticated management API exposes:

- `GET /v1/cache`: active configuration, weighted memory statistics, physical main-database bytes, entry counts, cumulative store hits/misses/evictions/errors, and active fills. Disk values remain zero until the lazy database has opened.
- `POST /v1/cache/purge`: in shared-store modes commits the configuration with the next `cache.generation`, which every instance applies as a configuration update; in file mode it clears this instance's memory and disk entries. It returns `{"purged":true}` on success, including when caching is disabled, and `503` if cache maintenance cannot complete.
- `GET /v1/status`: proxy-level `cache_hits_total`, `cache_misses_total` and `cache_bypasses_total`. These describe HTTP decisions and therefore differ from store-internal counters.

Both endpoints require the configured admin bearer token. File replacement and `PUT /v1/config` can update cache settings while the gateway remains active; API updates require the current `ETag` in `If-Match`.

## Run the example

```sh
cargo build --locked
python3 examples/cache/run.py
```

The runner starts its own loopback origin and gateway, writes an instance-specific private disk directory, and first checks the generated configuration with `--check`. It then verifies a memory hit, file hot reload, ETag-protected API update, persistent disk reuse with the same public address across restart, and durable purge across another restart. It cleans up all processes and temporary files. Set `HANGANG_BINARY` to exercise another built binary.
