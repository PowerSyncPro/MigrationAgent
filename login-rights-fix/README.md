# FixLogonRights

Fixes the **"Allow log on locally"** (`SeInteractiveLogonRight`) local security policy on machines that have been migrated from Active Directory to **Entra ID (Azure AD join)**.

---

## The Problem

When a machine is migrated from AD to Entra, the local security policy in `secpol.msc` retains the original AD group entries under **User Rights Assignment → Allow log on locally**. These stale entries block Entra users from signing in interactively — even though the machine is correctly joined to Entra.

---

## What the Script Does

1. Exports the current local security policy using `secedit /export`
2. Replaces `SeInteractiveLogonRight` with the correct well-known local SIDs (see below)
3. Clears `SeDenyInteractiveLogonRight` to remove any explicit deny entries
4. Re-imports the modified policy using `secedit /configure`, scoped to `USER_RIGHTS` only — no other policy areas are touched
5. Re-exports and verifies the changes were applied, logging any mismatches
6. Runs `gpupdate /target:computer /force` to refresh computer policy

---

## Granted Logon Rights After Running

| SID | Group | Purpose |
|-----|-------|---------|
| `*S-1-5-32-544` | Administrators | Local admins |
| `*S-1-5-32-545` | Users | All local users — **this covers Entra-joined accounts** |
| `*S-1-5-32-551` | Backup Operators | Standard inclusion |
| `Guest` | Guest | Local Guest account |

> Entra users are added to the local **Users** group (`S-1-5-32-545`) during Entra join, so granting this group interactive logon rights is what unblocks them.

---

## Requirements

- Must be run as **Administrator**
- Windows 10 / 11
- Machine must already be Entra-joined
- `secedit.exe` and `gpupdate.exe` must be available (standard on all Windows editions)

---

## Usage

```powershell
.\FixLogonRights.ps1
```

No parameters. Run from an elevated PowerShell prompt.

---

## Log File

`C:\Temp\Fix-SeInteractiveLogonRight.log`

The log is cleared on each run. Check it to confirm:
- What the original values were
- Whether the import succeeded
- Whether verification passed
- gpupdate exit status

---

## After Running

**Reboot the machine** before testing Entra user sign-in. Some policy changes require a full restart to propagate to the login screen.
