# Threat model

This document states what blackbox protects against, what it does not, and
what it assumes.

## What blackbox claims

If `blackbox verify` reports a log as intact against a public key, and the
latest checkpoint was kept somewhere the attacker could not change, then:

1. Every entry in the log was written by a gateway holding the matching
   private key.
2. No entry has been changed since it was written.
3. No entry has been removed, inserted, or reordered.
4. No entry up to the latest checkpoint has been removed from the end.

It also flags, but does not prevent, suspicious agent behaviour (see below).

## Assets

- **The log**: the record of what agents asked and what models returned.
- **The signing key**: whoever holds it can write entries that verify.
- **Checkpoints**: signed statements of how long the log was at a point in time.

## Attackers and what happens

| Attacker | Can do | Detected by |
|---|---|---|
| Edits an entry in the log file | Change any bytes | Hash mismatch on that entry |
| Deletes or inserts an entry | Remove or add lines | Sequence gap or broken back-link |
| Reorders entries | Swap lines | Sequence or back-link mismatch |
| Edits an entry and recomputes the whole chain | Produce a consistent chain | Signatures fail without the private key |
| Deletes entries from the end | Leave a valid signed prefix | Log shorter than a checkpoint |
| Forges a checkpoint | Write a fake checkpoint line | Checkpoint signature fails |
| Replaces the log with one signed by another key | Present a different log | `verify` checks against the auditor's copy of the public key |

## Agent behaviour that is flagged

blackbox sees the full conversation on every call, so it can notice when an
agent, or something that has taken control of it, misrepresents what happened:

- tool results for calls the model never made (`orphan_tool_result`), as in a
  prompt injection that fakes an approval;
- earlier messages or the model's tool calls changed between turns
  (`history_rewritten`) or dropped (`history_truncated`);
- tools or the system prompt changed mid-session;
- a different model answering than the one requested;
- high-risk tools requested, including tool calls the model wrote as text.

These are flags for review, not blocks. blackbox does not stop a call.

## Assumptions

- **The private key is protected.** It is created with owner-only permissions.
  An attacker who has the key can write a log that verifies. Keep it on the
  gateway host only, and rotate it if the host may be compromised.
- **The auditor's public key is genuine.** Verification against an attacker's
  public key proves nothing. Distribute the public key separately from the log.
- **Checkpoints leave the gateway host.** If the attacker controls every copy of
  the checkpoints, they can truncate the log and the checkpoint file together.
  Ship checkpoints from stdout to a log collector or another machine.
- **Agents go through the gateway.** blackbox records only traffic sent to it.
  Network policy should make the gateway the only route to the model server.

## Not covered

- **A compromised gateway host.** An attacker with root on the gateway can read
  the key and write false entries going forward. blackbox protects records
  already written and checkpointed elsewhere, not the future output of a
  compromised machine.
- **Agent identity.** Agent, session, and principal names come from request
  headers and are recorded as `self_declared`. A misbehaving agent can claim
  any name. Gateway-issued agent credentials are planned.
- **What tools actually did.** blackbox sees what the model asked for and what
  the agent reported back, not the tool execution itself. Auditing tool
  servers directly is planned.
- **Concurrent calls in one session.** If several agents share a session ID and
  call at the same time, history checks can raise false alarms. Sub-agents
  should use their own session ID with `X-Blackbox-Parent-Session`.
- **Crash window.** With group commit, a hard crash can lose up to about 50 ms
  of entries. The loss is flagged at next start. `--sync always` removes the
  window at a cost in throughput.
- **Confidentiality.** The log contains full prompts and responses in plain
  text. It is created with owner-only permissions but is not encrypted.
- **Detection heuristics.** Tool calls written as text are found by pattern,
  and can be missed or over-reported.
