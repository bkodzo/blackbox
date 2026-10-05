# Configuration

## Settings

`blackbox serve` takes settings as flags or from a JSON file passed with
`--config`. Flags override the file. Unknown, misspelled, or repeated settings
in the file are rejected.

| Flag | JSON key | Default | Meaning |
|---|---|---|---|
| `--upstream` | `upstream` | required | Base URL of the model server |
| `--listen` | `listen` | `127.0.0.1:8080` | Address to listen on |
| `--log` | `log` | `blackbox.jsonl` | Audit log |
| `--checkpoints` | `checkpoints` | `blackbox.checkpoints.jsonl` | Checkpoint file (required) |
| `--key` | `key` | `~/.blackbox/key.ed25519` | Private signing key |
| `--risk` | `risk_map` | none | Risk map (see [examples/risk.json](../examples/risk.json)) |
| `--sync` | `sync` | `group` | `group` (batched fsync) or `always` (fsync every entry) |
| `--max-body` | `max_body_bytes` | 32 MiB | Bytes of each body stored; hashes always cover every byte |
| `--max-request` | `max_request_bytes` | 64 MiB | Larger requests are refused with 413 and recorded |
| `--max-in-flight` | `max_in_flight` | `64` | Requests handled at once; more are refused with 503 and recorded |
| `--checkpoint-stdout` | `checkpoint_stdout` | `true` | Also print checkpoints to stdout |
| `--checkpoint-records` | `checkpoint_records` | `100` | Write a checkpoint at least every this many entries |
| `--checkpoint-interval` | `checkpoint_interval` | `30s` | Write a checkpoint at least this often while entries are written |
| `--stream-idle-timeout` | `stream_idle_timeout` | `5m` | Cancel a response that makes no progress for this long |
| `--allow-upgrades` | `allow_upgrades` | `false` | Allow protocol upgrades, whose traffic is not recorded (default: refuse with 501) |
| `--fail-open` | `fail_open` | `false` | Keep forwarding if the log fails (default: refuse and exit) |
| `--body-read-timeout` | `body_read_timeout` | `1m` | Limit for reading a request body |
| `--upstream-timeout` | `upstream_timeout` | `10m` | Limit for the model server to start responding |
| `--shutdown-timeout` | `shutdown_timeout` | `30s` | Grace period for calls in flight at shutdown |

Example file:

```json
{
  "upstream": "http://127.0.0.1:9000",
  "log": "/var/lib/blackbox/blackbox.jsonl",
  "checkpoints": "/var/lib/blackbox/blackbox.checkpoints.jsonl",
  "risk_map": "/etc/blackbox/risk.json",
  "shutdown_timeout": "1m"
}
```

## Agent headers

Agents can describe themselves with optional headers. They are recorded and
then removed before the request is forwarded.

| Header | Recorded as |
|---|---|
| `X-Blackbox-Session` | `session.id`: groups the calls of one agent run |
| `X-Blackbox-Parent-Session` | `session.parent_id`: links a sub-agent to the run that started it |
| `X-Blackbox-Agent` | `agent.id` |
| `X-Blackbox-Agent-Version` | `agent.version` |
| `X-Blackbox-Principal` | `principal`: the person or service the agent acts for |

Calls without a session header are still grouped by conversation.

## Risk map

A JSON object keyed by tool name. `risk` is `low`, `medium`, or `high`; tools
not listed are recorded as `unknown`.

```json
{ "run_shell": { "risk": "high", "category": "execute", "says": "ran a command: {cmd}" } }
```

## Exit codes of `blackbox verify`

| Code | Meaning |
|---|---|
| 0 | The log is intact |
| 1 | The log or its checkpoints were tampered with |
| 2 | The log is intact, with warnings (for example an unclean shutdown) |
| 3 | Verification could not run (missing log, key, or checkpoint file, or a bad flag) |

`verify` requires the checkpoint file. Pass `--no-checkpoints` to verify a log
without one; removals from the end of the log then cannot be detected.

## Health endpoint

`GET /_blackbox/health` returns 200 with the latest sequence number and hash,
or 503 if the audit log has failed.
