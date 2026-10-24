# Key management

SAT-SA keeps two kinds of secrets: the **pseudonymisation key** and the **rule-pack signing key**.
This page covers where each one lives, how to back it up, and what rotating it does.

## Pseudonymisation key

Ingestion replaces analyst names, account names and similar identifiers with HMAC-SHA256
pseudonyms (`satsa.ingest.pseudonymise`). A pseudonym only links across periods while the key
stays the same. If the key changes, the same analyst gets a new pseudonym and longitudinal
analysis breaks without any error.

### Where it lives

`data/secrets/pseudonym_keys.json`. This is inside the data directory, so it is inside the
Compose `./data` volume and survives container recreation. No HTTP route serves it.
- **On POSIX** the directory is created `0700` and the file `0600`.
- **On Windows** they inherit the data folder's ACL, so restrict that folder to the service
  account.

Before Phase 2 the key was a file named `.satsa_salt` in the process's working directory. In a
container that directory was not persisted: recreating the container silently generated a new
key. **Pseudonyms ingested before and after such a recreation do not link, and nothing can repair
that.**

### Upgrading

The first ingestion or `satsa migrate` after the upgrade imports `.satsa_salt` byte for byte as
key version 1. It does not delete or change the old file, and existing pseudonyms stay valid.
Run `satsa keys status` to see the key id. Once a backup that contains `data/secrets/` is
verified, you may remove the old file.

### When the key is missing

When data exists but the key does not, SAT-SA refuses to make a new one. Ingestion and
`satsa migrate` stop with `PseudonymKeyMissing`. Restore `data/secrets/` from a backup, or put
`.satsa_salt` back.

Only if the key is truly lost:

```
satsa keys init --new-key-breaks-linkage
```

This records the break in the keyring (`origin`) and in the audit log.

### Rotation

```
satsa keys rotate --i-understand-pseudonyms-will-not-link
```

Rotation adds a new version and makes it current. Earlier versions are kept, because old batches
were pseudonymised with them.
- **What changes:** every batch records the id of the key it used (`batches.pseudonym_key_id` in
  `data/catalog.db`), and rotation is written to the audit log.
- **What it costs:** pseudonyms after the rotation do not match those before it. Peer and trend
  analyses that follow an individual analyst across the rotation will treat them as different
  people.
- **Do not rotate on a schedule.** Rotate when you believe the key was exposed. Anyone holding
  the key and a candidate name can re-derive that name's pseudonym.

The key id (`v<version>:<12 hex>`) is a fingerprint of the key, not the key itself.
`satsa keys status` shows ids, dates and origins, never key material.

## Rule-pack signing key

`SATSA_RULEPACK_SECRET` is passed in through the environment (Compose passes it through from the
host). It is not stored by SAT-SA. Keep it in the host's secret store. Without it, rule-pack
export and import are disabled.

## Backups and custody

`satsa backup` copies `data/secrets/` together with the databases and published data, because a
restore without the key cannot pseudonymise new data consistently (docs/backup_restore.md).
- A backup therefore contains secrets. Encrypt it (`satsa backup --encrypt`) and keep the backup
  passphrase apart from the backup media.
- Local file permissions do not protect against a privileged host administrator. Volume encryption
  and who holds the recovery keys are deployment decisions, outside the application.
