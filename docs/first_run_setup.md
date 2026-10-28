# First-run setup and demo mode

## Production (the default)

A new deployment starts empty, with no accounts, no data and no published passphrases. Whether
it is a demo is decided once, when `data/satsa.db` is created, and stored in the database
(`deployment_settings.mode`). Setting or clearing an environment variable later does not change
it.

1. **Start the platform.** For example `docker compose up -d`, or `python entrypoint.py`. The
   console prints:

   ```
   [+] PRODUCTION deployment, not set up yet. Open the Admin Portal (:8000) and use
       this one-time setup token (also in data/secrets/setup_token):
       <token>
   ```

   A restart prints the same token until setup is done.
2. **Open the Admin Portal** (`:8000`) and sign in. Before setup, sign-in redirects to `/setup`.
   Enter:
   - the token;
   - the first administrator's username and passphrase (at least 12 characters, not a
     published default);
   - the deployment's name;
   - its time zone (IANA name, e.g. `Asia/Kolkata`; data stays in UTC);
   - how long to keep the files of failed or held uploads, and how many local backups to keep.

   The page also shows whether the portals are reachable from other machines and whether TLS is
   on. TLS itself is configured with `SATSA_TLS_CERT` and `SATSA_TLS_KEY`
   (docs/deployment_ops.md, section 1.3).
3. **Results of setup.**
   - The token is deleted and `/setup` returns 404.
   - The setup is audited in both audit logs.
   - Wrong tokens are logged. After 5 failures in 15 minutes, setup is refused for 15 minutes.
4. **Sign in** as the new administrator. In production the portal then asks you to enrol an
   authenticator app (TOTP, offline) and shows 10 recovery codes once; keep them apart from the
   device (`docs/security/mfa.md`).
5. **Create analyst and examiner accounts** under *Users → Create New User*. The *Initial
   Passphrase* box is filled with a random 16-character passphrase; leave *Require Password Reset
   on Initial Login* ticked. Give the username and initial passphrase to the person yourself: the
   portal does not send them. At their first SAT-SA sign-in (`:8001`) they must choose their own
   passphrase before anything else opens. A forgotten passphrase is replaced with **Reset** on the
   user's row.
6. **Import data deliberately** through SAT-SA's upload page or `satsa ingest`, either real
   submissions or a sample you choose. A production deployment never loads demonstration data
   by itself, and its "Load Demonstration Data" action is refused (HTTP 403).

Without a browser, the same setup can be done from the shell. Shell access to the data directory
stands in for the token:

```
SATSA_SETUP_PASSPHRASE='...' satsa setup --admin-username ops-admin --deployment-name "NCIIPC SOC supervision"
satsa deployment show
```

## Demo mode

A demo runs with `SATSA_DEMO=1` on a **separate data directory**. The launchers keep everything
in `demo-run/` (its own `data/`, `reports/` and a copy of `config/`), so the production `data/`
is never touched:

```
start-demo.bat                  # Windows: Docker if installed, otherwise this project's Python
python entrypoint.py --demo     # any OS, without Docker
```

`stop-demo.bat` stops it; delete `demo-run/` to start the demo afresh. With Compose directly:

```
SATSA_DEMO=1 SATSA_DATA_DIR=./demo-run/data SATSA_REPORTS_DIR=./demo-run/reports \
SATSA_CONFIG_DIR=./demo-run/config SATSA_CONTAINER_NAME=satsa-demo docker compose -p satsa-demo up -d
```

(copy `config/` to `demo-run/config/` first).

- **Accounts.** The demonstration accounts are created, with published passphrases
  (`README.md`). Both login pages have one-click buttons for them (*Analyst*, *Examiner* on
  SAT-SA; *nciipc_admin*, *admin* on the Admin Portal), and they owe no passphrase change.
- **Data.** Synthetic data is loaded by a `demo_seed` job, which the worker runs.
- **Labelling.** Every page of both portals shows a "DEMONSTRATION DEPLOYMENT" banner.
- **Isolation.** A process started with `SATSA_DEMO=1` against a production database refuses to
  start (`DemoIsolationError`). Demonstration accounts and data never enter a production
  deployment.

## Deployments created before modes existed

`satsa migrate` (or the first start) records them as production, with `mode_origin` saying so.
Their existing accounts stay, so no setup is pending. Demonstration accounts in such a database
(e.g. `analyst` with `ChangeMe-Analyst#2026`) are forced to change their passphrase at first
login, because this is production. Its login pages show no one-click buttons. Remove or rotate
these accounts through the Admin Portal.
