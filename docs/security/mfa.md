# Administrator MFA

Admin Portal accounts use a second factor: a TOTP code from any authenticator app (RFC 6238,
SHA-1, 6 digits, 30 seconds). It works fully offline, with no SMS, e-mail or cloud service.

## Policy

`SATSA_ADMIN_MFA=required|optional`. When unset, MFA is **required** in a production deployment
and **optional** in a demo deployment (docs/first_run_setup.md).

While it is required, an administrator without a factor is sent to `/mfa/setup` after signing in
and can do nothing else. An account still using a default or reset passphrase changes that first.

## Enrolment

1. Sign in. The portal shows a key, plus an `otpauth://` URI to paste into an authenticator on a
   separate device.
2. Enter one code to confirm.
3. Ten **recovery codes** are shown once. Each works once instead of a code. Keep them apart from
   the device, e.g. printed and sealed. They are stored only as hashes.

## Signing in

After the passphrase, the portal asks for a code at `/login/mfa`.
- **Clock drift:** codes from the previous and next 30-second steps are accepted.
- **No replay:** a code that was already used is refused.
- **Lockout:** after 5 wrong codes the session ends and sign-in starts again.
- **Audit:** every outcome is written to the admin audit log (`ADMIN_MFA_OK`, `ADMIN_MFA_FAIL`),
  including which method was used and how many recovery codes remain.

## Lost device

Another administrator opens the user's page and chooses **Reset second factor** (`MFA_RESET`,
audited). The user enrols again at their next sign-in. Nobody can reset their own factor.

If the only administrator has lost both the device and the recovery codes, run, on the host:

```
SATSA_ADMIN_MFA=optional
```

Restart the Admin Portal, sign in, remove the factor and enrol again, then remove the override.
This is a host-level action. Record it in your change log.

## Limits

- **The secret can be read on the host.** A TOTP secret must be usable by the server, so whoever
  can read `data/satsa.db` can read it. Disk encryption and host custody cover this.
- **Admin Portal only.** SAT-SA analyst and examiner accounts do not have MFA yet
  (docs/security/asvs_checklist.md, V2.8).
