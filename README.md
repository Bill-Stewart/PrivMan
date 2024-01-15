# PrivMan

**PrivMan** is a Windows console (text-based, command-line) program that provides privilege/right management functions.

## AUTHOR

Bill Stewart - bstewart at iname dot com

## LICENSE

**PrivMan** is covered by the GNU Public License (GPL). See the file `LICENSE` for details.

## SYNOPSIS

**PrivMan** is an open-source alternative to the **ntrights** utility found in the Windows Resource Kit. Differences between **PrivMan** and **ntrights**:

* **PrivMan** supports adding and removing multiple privileges/rights, whereas **ntrights** only supports one privilege/right at a time.

* **PrivMan** can test whether an account has one or more privileges/rights, but **ntrights** cannot.

* **PrivMan** can list accounts with a specified privilege/rights, but **ntrights** cannot.

* **PrivMan** can report on all accounts and assigned privileges/rights, but **ntrights** cannot.

* **PrivMan** doesn't currently support changing privileges/rights on a remote computer.

* **PrivMan** doesn't support adding an entry to the event log.

## USAGE

* Command-line parameters (e.g., `-g`, `-r`, `-t`, `--displayname`, etc.) are case-sensitive.
* Names of privileges and rights (e.g., `SeServiceLogonRight`, etc.) are not case-sensitive.
* The `-q` parameter suppresses status and error messages.
* The `"`_privileges_`"` parameter specifies a space-delimited list of privileges and/or rights, enclosed within `"` characters.
* Most commands require administrative permissions (i.e., "Run as administrator").
* Accounts can be specified by name or SID (e.g., S-1-5-32-544).

---

### GRANT OR REVOKE PRIVILEGES/RIGHTS

`PrivMan -a` _account_ [`-g`|`-r`] `"`_privileges_`"` [`-q`]

For the specified account, grants (`-g`) or revokes (`-r`) one or more privileges/rights. Examples:

* `PrivMan -a MyServiceAcct -g SeServiceLogonRight`
* `PrivMan -a AdminUser -r "SeServiceLogonRight SeNetworkLogonRight"`

---

### REVOKE ALL PRIVILEGES/RIGHTS

`PrivMan -a` _account_ `--revokeall` [`-q`]

This command removes all privileges/rights from the specified account. It's recommended to find out what privileges/rights were assigned to the account before using this command, so you can put restore any privileges/rights that might have broken something. USE WITH CAUTION.

---

### TEST ACCOUNT FOR PRIVILEGES/RIGHTS

`PrivMan -a` _account_ `-t` `"`_privileges_`"` [`-q`]

Returns an exit code of 0 if the account does not have all specified privileges/rights, or 1 if the account has all specified privileges/rights. Any other exit code indicates an error.

---

### LIST AN ACCOUNT'S PRIVILEGES/RIGHTS

`PrivMan -a` _account_ `--list`

---

### LIST ACCOUNTS WITH SPECIFIED PRIVILEGE/RIGHT

`PrivMan --privilegeaccounts` _privilege_

Example: `PrivMan --privilegeaccounts SeServiceLogonRight` outputs a list of accounts that have the `Log on as a service` right.

---

### OUTPUT U.S. ENGLISH DISPLAY NAME OF PRIVILEGE/RIGHT

`PrivMan --displayname` _privilege_

Example: `PrivMan --displayname SeServiceLogonRight` outputs "Log on as a service".

---

### OUTPUT LIST OF ALL PRIVILEGES/RIGHTS

`PrivMan --listall`

This command outputs a comma-delimited (CSV) list of all privileges/rights and display names.

---

### OUTPUT COMMA-SEPARATED REPORT OF ACCOUNTS AND PRIVILEGES

---

`PrivMan --csvreport`

This command outputs a comma-delimited report of all accounts and privileges/rights assigned to each account.

---

## VERSION HISTORY

### 0.0.1 (2024-01-15)

* Initial version.
