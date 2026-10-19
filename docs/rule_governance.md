# Rule governance: how a threshold change is proposed, approved and put in force

`config/rules.yaml` holds the thresholds every assessment uses. A change to it is a **version**
in `rule_pack_versions` (migration v10, `satsa.rules.lifecycle`), never an untracked edit.

```
draft -> approved -> active -> retired
draft | approved -> rejected
```

| Step | Who | Where | What happens |
|---|---|---|---|
| Propose | an analyst | Rule Tuning: *Save* | A **draft** is recorded: the full proposed `rules.yaml`, the version it is based on and what changed. Nothing on disk changes and nothing is re-assessed. *Preview Effect* shows what the draft would change (a dry-run assessment, nothing stored). |
| Approve | an analyst or examiner who is **not the author** | Rule Tuning or *Rule Changes* (examiners) | The draft becomes **approved**, with the approver and an optional note. The author can never approve their own change: the application refuses it and a database `CHECK` does too. |
| Reject | an analyst or examiner | same | The draft or approved version is **rejected**, with a reason. It can no longer be approved or put in force. |
| Put in force | an analyst | Rule Tuning | An approved version is written to `config/rules.yaml` atomically and becomes **active**; the previous active version is **retired**. A re-assessment of the latest period is queued. Only a version based on the version currently in force can be activated: if another change went in first, propose again from the current configuration. |

At most one version is active (a partial unique index). Every step is in the audit chain
(`rule_version_proposed`, `_approved`, `_rejected`, `_activated`).

## Other ways a configuration changes

- **First use.** The configuration in force when versioning began is recorded as version 1,
  `adopted`.
- **Signed rule pack.** A pack from the issuing authority (`/tuning/import-pack`) is verified
  (HMAC signature and SHA-256 of every file) and recorded as active, with the signature as its
  approval (`approved_by = signature:<first 12 hex>`).
- **An edit outside the lifecycle** (by hand, or by restoring files). Assessments use what is on
  disk, so the edit is recorded as a new active version, `external_edit`, the event is audited,
  and Rule Tuning shows a warning the first time it sees it. Avoid this: it bypasses approval.
- **Demonstration deployments.** *Save* puts the change in force at once, without a second
  person, and records it with the note "demonstration deployment: activated without a second
  approval". Production deployments never do this.

## Reproducibility

Each assessment run stores its complete configuration (`run_config_snapshots`) and analytical
fingerprint, so `satsa replay <run id>` reproduces a run under the version that was in force
then, whatever has been activated since.
