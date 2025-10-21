***

# Cypher Command Reference

This document provides a detailed guide to all available commands in the Cypher CLI.

Arguments in `<angle brackets>` are required, while those in `[square brackets]` are optional.

---

### ## `add`

Adds a new password entry to the current vault. The command will interactively prompt you for the service, username, password, and optional notes if they are not provided as arguments.

* **Aliases**: `a`
* **Usage**: `cypher> add [service] [username]`

#### **Arguments**
* **`[service]`** (Optional): The name of the service (e.g., "google", "github").
* **`[username]`** (Optional): The username or email for the service.

#### **Examples**
* `cypher> add` (Interactive mode)
* `cypher> add github MyUser` (Prompts for password and notes)

---

### ## `get`

Retrieves a password entry. If a username is not specified and multiple accounts exist for the given service, a menu will be displayed to let you choose.

* **Aliases**: `g`
* **Usage**: `cypher> get <service> [username]`

#### **Arguments**
* **`<service>`** (Required): The name of the service to retrieve.
* **`[username]`** (Optional): The specific username to retrieve.

#### **Examples**
* `cypher> get google`
* `cypher> get aws admin-user`

---

### ## `list`

Lists all password entries stored in the current profile, showing the service and username for each.

* **Aliases**: `ls`
* **Usage**: `cypher> list`

---

### ## `delete`

Permanently removes a password entry from the vault. This action requires confirmation unless the `--force` flag is used.

* **Aliases**: `rm`, `del`
* **Usage**: `cypher> delete <service> <username> [--force]`

#### **Arguments**
* **`<service>`** (Required): The service name of the entry to delete.
* **`<username>`** (Required): The username of the entry to delete.
* **`--force` / `-f`** (Optional): Skips the confirmation prompt.

#### **Examples**
* `cypher> delete twitter old_account`
* `cypher> delete facebook test_user --force`

---

### ## `update`

Updates the password or notes for an existing entry. The command will interactively prompt for the new values.

* **Aliases**: `edit`, `modify`
* **Usage**: `cypher> update <service> <username>`

#### **Arguments**
* **`<service>`** (Required): The service name of the entry to update.
* **`<username>`** (Required): The username of the entry to update.

---

### ## `search`

Searches for entries by service name. The search is case-insensitive and matches partial strings.

* **Aliases**: `find`, `s`
* **Usage**: `cypher> search [query]`

#### **Arguments**
* **`[query]`** (Optional): The text to search for within service names. If omitted, you will be prompted.

#### **Example**
* `cypher> search git` (Would match "github", "gitlab", etc.)

---

### ## `generate`

Generates a new, cryptographically secure password.

* **Aliases**: `gen`, `password`
* **Usage**: `cypher> generate [options]`

#### **Options**
* **`--length <num>` / `-l <num>`**: Sets the password length (Default: 16).
* **`--no-uppercase`**: Excludes uppercase letters.
* **`--no-lowercase`**: Excludes lowercase letters.
* **`--no-digits`**: Excludes numbers.
* **`--no-symbols`**: Excludes symbols.

#### **Examples**
* `cypher> generate` (Generates a 16-character password)
* `cypher> generate --length 24 --no-symbols`

---

### ## `export`

Creates a secure, encrypted backup of the currently loaded profile.

* **Aliases**: `backup`
* **Usage**: `cypher> export [export_path]`

#### **Arguments**
* **`[export_path]`** (Optional): The file path for the backup. If omitted, a default timestamped name is used.

---

### ## `switch`

Logs out of the current profile and returns to the profile selection screen.

* **Aliases**: `logout`
* **Usage**: `cypher> switch`

---

### ## `clear`

Clears the terminal screen.

* **Aliases**: `cls`, `c`
* **Usage**: `cypher> clear`

---

### ## `delete-profile`

Permanently deletes a profile and all of its associated data. This action is irreversible and cannot be performed on the currently loaded profile.

* **Aliases**: `remove-profile`
* **Usage**: `cypher> delete-profile <profile_name>`

#### **Arguments**
* **`<profile_name>`** (Required): The exact name of the profile to delete.

### ## General Options

* **`--help` / `-h`**: Show the detailed help message.
* **`--version` / `-v`**: Display the application version.