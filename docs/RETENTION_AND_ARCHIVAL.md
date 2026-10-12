# Conservative network-flow retention

The retention CLI never deletes alerted NetworkEvent records, Alert records, Analyst Notes, or Audit history. It is intentionally a **manual, dry-run-first** maintenance action.

```powershell
networkpulse archive --before-days 30 --output data/archive/flows-2026-10.jsonl
networkpulse archive --before-days 30 --output data/archive/flows-2026-10.jsonl --commit
```

`--commit` writes a new newline-delimited JSON archive, flushes/fsyncs, records a SHA256 + count manifest, and then transactionally removes only matching **unalerted** rows. If export or database deletion fails, the database remains recoverable. A crash between export and deletion can leave an archive with flows still present; verify the DB and manifest before retrying to a **new** filename.

Caveats: this is a small/medium DB operator tool, not a regulated retention implementation. No encryption at rest, object-store replication, legal hold, auditable retention approval, automatic schedule, or point-in-time restores are provided. For production, implement dedicated secure archive storage, encryption, restore drills, partition expiry and durable metadata lineage. `--max-rows` defaults to 5000; schedule explicit, supervised runs rather than blindly purging all rows.
