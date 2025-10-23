
# Cypher: A Secure Command-Line Password Manager

Cypher is a command-line password manager built for developers, sysadmins, and anyone who works primarily in a terminal environment. It provides a text-based interface to manage sensitive credentials, using strong cryptographic principles to ensure data security.

-----

## 🚀 Key Features

  * **State-of-the-Art Encryption**: Utilizes **AES-256-GCM** for encryption and **Argon2id** for key derivation, ensuring your data is protected with industry-leading standards.
  * **Intuitive Command-Line Interface**: A clean, color-coded, and responsive UI that makes password management fast and easy.
  * **Multi-Profile Support**: Securely manage separate vaults for different users or contexts (e.g., personal, work) with complete data isolation.
  * **Secure Session Management**: Features an automatic session timeout with non-blocking warnings to protect against unauthorized access on an unattended machine.
  * **Built-in Secure Password Generator**: Create strong, random passwords based on user-defined criteria.
  * **Atomic Saves & Data Integrity**: Prevents data corruption by using atomic file-writing operations. Your database is never left in a partially saved or broken state.
  * **Secure Backup & Export**: Allows you to export your encrypted data for backup purposes.

-----

## 🛡️ Security First: A Core Design Principle

Security is not an afterthought in Cypher; it is the foundation. The application was built from the ground up with a focus on mitigating modern threats.

  * **Cryptographically Sound**: Uses separate, derived keys for encryption (AES-256-GCM) and data integrity (HMAC-SHA256). This prevents chosen-ciphertext attacks and ensures data cannot be tampered with.
  * **Nonce Collision Protection**: Implements a tracker to prevent nonce reuse with AES-GCM, a critical safeguard against catastrophic key compromise.
  * **Secure Memory Handling**: Sensitive data like the master password and recovery phrases are handled in protected memory buffers that are securely wiped after use, minimizing their exposure.
  * **Brute-Force Prevention**: Login attempts are rate-limited to slow down and deter brute-force attacks on the master password.
  * **Path Traversal Protection**: All profile path inputs are strictly sanitized and validated to prevent malicious path traversal attacks.
  * **Verified Recovery Phrases**: The recovery system is explicitly verified during setup to ensure you can always regain access to your account.

-----

## ⚙️ Installation

You can install Cypher directly from GitHub using `pip`, which will automatically handle dependencies and make the `cypher` command available system-wide.

```bash
pip install git+https://github.com/Kanishk-C/cypher.git
```

That's it\! The application is now installed.

### Developer Installation (for contributing)

If you wish to modify the source code, you should install the project in "editable" mode.

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Kanishk-C/cypher.git
    cd cypher
    ```
2.  **Install in editable mode**:
    ```bash
    pip install -e .
    ```

This allows your changes to be reflected immediately without needing to reinstall.

-----

## 💻 Usage

Once installed, you can run the application from any directory by simply typing the command:

```bash
cypher
```

### First Time Use

On your first run, you will be guided through a secure setup process to create your first profile and master password. A unique recovery phrase will be generated—**store it in a safe place\!**

### Available Commands

| Command | Description |
| :--- | :--- |
| `profile` | Manage user profiles (create, list, switch, delete). |
| `add` | Add a new password entry for a service. |
| `get` | Retrieve and copy a password for a service. |
| `update` | Update an existing entry's password or notes. |
| `delete` | Remove a password entry. |
| `list` | List all services stored in the current profile. |
| `gen` | Generate a new secure password. |
| `export` | Export the current profile to an encrypted backup file. |
| `lock` | Manually lock the session. |
| `help` | Display the help menu. |
| `exit` / `quit` | Securely save the session and exit the application. |

-----

## ✅ Project Status: Stable (v1.0.0)

This project has undergone a comprehensive code and security review. All identified critical issues, including potential data loss on update and path traversal vulnerabilities, **have been fixed and verified**. Cypher is considered stable and ready for production use.

## 🗺️ Roadmap (Future Enhancements)

Here is the revised roadmap incorporating your ideas, the original list, and some additional suggestions.

### Core Functionality

  * [ ] **Import Functionality**: Allow importing from encrypted `.cypher` backups and common formats (e.g., CSV, JSON).
  * [ ] **Change Master Password**: A secure feature to re-encrypt a profile's vault with a new master password.
  * [ ] **Clipboard Integration**: Automatically copy passwords to the clipboard using the `get` command and clear it after a set time (e.g., 45 seconds).

### Security & Auditing

  * [ ] **Vault Health Report**: Create a command (`audit` or `health-check`) that generates an overall security score for the vault based on weak, reused, or old passwords.
  * [ ] **Password History**: Store a secure, limited history for each entry, allowing users to view and restore previous passwords.
  * [ ] **Data Breach Monitoring**: Integrate with an API like "Have I Been Pwned" to check if any usernames/passwords in the vault have appeared in known data breaches.

### User Experience & Features

  * [ ] **Dedicated Entry Types**: Add support for storing different types of secrets, such as API Keys, Secure Notes, or credit card information.
  * [ ] **Custom Fields**: Allow users to add their own custom key-value fields to any entry for maximum flexibility.
  * [ ] **Log Rotation**: Automatically rotate the `cypher_activity.log` file to manage its size over time.
  * [ ] **Database Integrity Checks**: Add an optional startup check to verify the database schema and check for corruption.

### Long-Term Vision

  * [ ] **GUI Version**: Develop a graphical user interface (GUI) for desktop users.
  * [ ] **Browser Integration**: Create browser extensions to auto-fill passwords.
  * [ ] **2FA/TOTP Support**: Store and generate Time-based One-Time Password (TOTP) codes.

## 🙌 Contributing

Contributions, issues, and feature requests are welcome\! Feel free to check the [issues page](https://github.com/Kanishk-C/cypher/issues).

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
