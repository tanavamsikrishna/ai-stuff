---
name: macos-sandbox-profile-generator
description: Expert generator for macOS sandbox-exec (Seatbelt) SBPL profiles. Specializes in Last-Match-Wins logic to safely restrict file, network, and other system resources.
---

# Sandbox Rules Generator

<instructions>
You are tasked with generating or modifying macOS `sandbox-exec` (SBPL) profiles.
Read the `<rules>` carefully, as macOS sandbox logic is highly counter-intuitive and differs from standard firewall or permission models (like iptables or AWS SG).
Use the `<template>` as your starting point when creating a new profile.
</instructions>

<rules>
  <rule name="Rule Priority">
    **Last-match-wins**: Rules are evaluated top-to-bottom. If multiple rules match a path, the **last** rule that matches determines the final outcome. Global actions without paths (like `(deny file-write*)`) act as defaults for that action, but specific path rules will always override them.
  </rule>
  <rule name="Critical Pattern: Allow Before Deny">
    When carving out a specific restriction from a broader permission, the broad **allow** rules MUST come BEFORE the specific **deny** rules. If you deny a child directory first and then allow the parent directory later, the parent allow will override the child deny.

    **WRONG (doesn't work - child deny is overridden):**
    ```lisp
    (deny file-read* (subpath "/Users/vamsi/.ssh"))  ; Deny first
    (allow file-read* (subpath "/Users/vamsi"))        ; Allow parent after (OVERRIDES the deny!)
    ```

    **CORRECT (works - child deny overrides parent allow):**
    ```lisp
    (allow file-read* (subpath "/Users/vamsi"))        ; Allow parent first
    (deny file-read* (subpath "/Users/vamsi/.ssh"))  ; Deny specific child after
    ```
  </rule>
  <rule name="Default Fallback">
    The `(allow default)` or `(deny default)` rule is special - it's evaluated as a **fallback** when no explicit path rule matches.
  </rule>
</rules>

<anti_patterns>
  - **Assuming First-Match-Wins:** Do not assume the first matching rule stops evaluation. It does not.
  - **Placing Denies at the Top:** Do not place sensitive file `deny` rules at the top of the file. If a subsequent broad `allow` rule (like allowing the home directory) matches the file, the sandbox will permit access, causing a security vulnerability.
</anti_patterns>

<template>
```lisp
(version 1)

; ====================================================
; SANDBOX PROFILE
; Establish broad allows first, then add specific denies at the end
; ====================================================

; ----------------------------------------------------
; 1. DEFAULT ALLOW (fallback for network, IPC, etc.)
; ----------------------------------------------------
(allow default)

; ----------------------------------------------------
; 2. GLOBAL DENY ALL FILE WRITES
; ----------------------------------------------------
(deny file-write*)

; ----------------------------------------------------
; 3. ALLOW FILE WRITES (exceptions)
; ----------------------------------------------------
(allow file-write* (subpath "/dev"))
(allow file-write* (subpath "/private/tmp"))
(allow file-write* (subpath "/private/var/folders"))
(allow file-write* (subpath (param "PWD")))        ; Current working directory
(allow file-write* (subpath "/Users/vamsi/.cache/uv"))  ; Python package cache

; ----------------------------------------------------
; 4. ALLOW FILE READS (minimal paths needed)
; ----------------------------------------------------
(allow file-read* (subpath "/usr"))              ; System binaries
(allow file-read* (subpath "/System"))           ; System libraries
(allow file-read* (subpath "/Users/vamsi/.pi"))      ; Pi agent extensions
(allow file-read* (subpath "/Users/vamsi/scripts"))  ; Scripts folder
(allow file-read* (subpath "/Users/vamsi/.cache/uv")) ; uv cache

; ----------------------------------------------------
; 5. DENY SENSITIVE FILE READS (last priority - overrides any broad allows)
; ----------------------------------------------------

; SSH and GPG keys
(deny file-read*
    (subpath "/Users/vamsi/.ssh")
    (subpath "/Users/vamsi/.gnupg"))

; Shell configuration and history
(deny file-read*
    (subpath "/Users/vamsi/.bash_history")
    (subpath "/Users/vamsi/.zsh_history")
    (subpath "/Users/vamsi/.zshrc")
    (subpath "/Users/vamsi/.bashrc")
    (subpath "/Users/vamsi/.zprofile")
    (subpath "/Users/vamsi/.bash_profile")
    (subpath "/Users/vamsi/.profile")
    (subpath "/Users/vamsi/.netrc"))

; Git credentials and config
(deny file-read*
    (subpath "/Users/vamsi/.gitconfig")
    (subpath "/Users/vamsi/.git-credentials")
    (subpath "/Users/vamsi/.config/gh"))

; Cloud/Infrastructure credentials
(deny file-read*
    (subpath "/Users/vamsi/.aws")
    (subpath "/Users/vamsi/.kube")
    (subpath "/Users/vamsi/.azure")
    (subpath "/Users/vamsi/.docker")
    (subpath "/Users/vamsi/.config/gcloud")
    (subpath "/Users/vamsi/.oci"))

; Package manager credentials
(deny file-read*
    (subpath "/Users/vamsi/.npmrc")
    (subpath "/Users/vamsi/.pypirc"))

; Personal files
(deny file-read*
    (subpath "/Users/vamsi/Desktop")
    (subpath "/Users/vamsi/Documents")
    (subpath "/Users/vamsi/Downloads")
    (subpath "/Users/vamsi/Pictures")
    (subpath "/Users/vamsi/Movies")
    (subpath "/Users/vamsi/Music")
    (subpath "/Users/vamsi/Applications")
    (subpath "/Users/vamsi/Library"))

; System files
(deny file-read*
    (subpath "/etc"))
```
</template>

<reference>
## Common Filters

| Filter | Matches |
|--------|---------|
| `(literal "/path/to/file")` | Exact file path only |
| `(subpath "/path/to/dir")` | Directory and ALL children recursively |
| `(regex "pattern")` | Paths matching regex (rarely needed) |

## File Permission Classes

| Class | Includes |
|-------|----------|
| `file-read*` | All read operations (open, read, getattr, etc.) |
| `file-write*` | All write operations (create, write, chmod, etc.) |
| `file-read` | Only open-for-read |
| `file-write` | Only open-for-write |

## Operations

| Operation | Purpose |
|-----------|---------|
| `file-read*` | Read files |
| `file-write*` | Write files |
| `network*` | Network access |
| `process*` | Process operations |
| `ipc*` | Inter-process communication |
| `signal` | Signal handling |
</reference>

<troubleshooting>
### Deny rules not working
- Ensure specific denies come AFTER broad allows (Last-match-wins)
- Ensure you are using `(subpath ...)` to correctly capture child directories.

### Can't run Python
- `(deny default)` blocks everything including running the interpreter
- `(deny file-write*)` without exceptions blocks uv cache
- Ensure `/Users/vamsi/.pi/agent/extensions/` is readable

### Binary files fail to read
- This is expected (UTF-8 decode error)
- Use `open(path, "rb")` for binary mode
</troubleshooting>