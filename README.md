# ansible-vars

*Manage vaults and variable files for Ansible.*

## TL;DR

Replaces the `ansible-vault` command with `ansible-vars`, which supports encrypting individual variables, not just entire files. Also provides a CLI and Python interface for querying and modifying Ansible variable files and vaults.

## Introduction

This project was motivated by a need to have Ansible vaults readable to humans and external programs like `grep` without a manual decryption step, while keeping secret values in these vaults secure from prying eyes. Ansible actually supports keeping vaults plain-text and only encrypting individual string variables, but this feature is not widely known or used and editing such files is not supported by the `ansible-vault` tool.

`ansible-vars` allows you to do the same things `ansible-vault` does (and more!), but not just for fully encrypted vaults, but also plain variable files and vaults with hybrid encryption (individually (un)encrypted variables). This is significantly more complex, as `ansible-vault` can be agnostic to the contents of the file it en-/decrypts, while hybrid encryption requires full round-trip parsing of a vault's Jinja2 YAML code.

The main features are:
- Create and edit vaults and variable files with hybrid encryption support.
- Continuously sync a decrypted copy of your vault file(s) to a specified directory.
- Programatically change a vault's variables from Python or from your shell (experimental).
- Compare different versions of a vault and optionally log changes.

Many convenience features have been implemented, such as:
- Convert any of your old fully encrypted vaults to a hybrid vault with just one command.
- Automatically load vault secrets from the Ansible configuration.
- Smart search paths for vault files and directories.
- Full bash/zsh completion.

The extensive help function (`ansible-vars [command] -h`) will explain each feature in detail.

## Installation

You need to have a current version of Python installed. The CLI and library have been tested in Python 3.12, but will likely work with earlier versions as well.

### Using a [virtual environment](https://docs.python.org/3/library/venv.html)

```sh
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate
# Install pip package
pip install ansible-vars
```

Note that the virtual environment must be active when using the command.

### Using [pipx](https://github.com/pypa/pipx)

```sh
# Install pipx, e.g. like this on Debian
sudo apt install pipx
# Install pip package globally using pipx
pipx install ansible-vars
```

### Shell completion

For `bash` and `zsh` users, shell completion for `ansible-vars` can be activated by adding this command to your shell RC file:

```sh
# Add to .bashrc/.zshrc in your user's home
# If you installed ansible-vars to a venv, the venv must be active when this command runs
eval "$(register-python-argcomplete ansible-vars)"
```

Alternatively, you can install the `argcomplete` completion system [globally](https://github.com/kislyuk/argcomplete#global-completion).

## Usage

The functions of `ansible-vars` are accessed by specifying a command as the first argument. You can quickly get relevant information by using the help function (`ansible-vars [command] -h`), optionally specifying the command you want more details about.

### Variable encryption

When editing a vault or variable file using `ansible-vars`, you can prefix any string value using the `!enc` tag to have it encrypted automatically:

```yaml
my_message: !enc this is a super secret message
```

The variable will turn into an Ansible encryption string when saving the file:

```yaml
my_message: !vault |-
  $ANSIBLE_VAULT;1.2;AES256;someid
  333533...
```

Encrypted variables will be displayed using this tag when editing, making it easy to view, modify, or decrypt their value on the fly.

### Vault secrets

**TL;DR:** Run `ansible-vars` from your Ansible home to auto-detect configured secrets. Add a custom secret using `-k <identifier> <passphrase>`.

To use any functions of `ansible-vars` that require encrypting or decrypting data, you need to provide one or multiple vault secret(s). If you're in an Ansible home directory when running the command, it tries to auto-detect configured vault secrets by calling the Ansible CLI API, which looks for a `vault_identity_list` in the Ansible configuration. You can also specify your own secrets as pairs of identifier and passphrase using `--add-key|-k <identifier> <passphrase>`. The identifier can be anything you want, although it should ideally be unique. Consider using an environment variable or in-line command to retrieve the passphrase from a secure location.

By default, the first loaded key is used for all encryption tasks. Note that auto-detected keys are inserted into the application's keyring *after* your explicitly added ones, so the first key you add will usually be the encryption key. If you want to make sure a certain key is used, reference its identifier using `--encryption-key|-K <identifier>`.

You can disable automatic key detection by flagging `--no-detect-keys|-D`. Use `ansible-vars keyring` to view all available keys.

You can customize the configuration file used for key detection via `--detection-source` or the environment. When a configuration file path is given, the file will be searched for a `vault_identity_list` and the corresponding secrets get loaded. When a directory path is given, `ansible-vars` will look for an `ansible.cfg` in that directory and perform the same loading procedure on that file. When left unset, Ansible checks if a configuration file path is set via its standard environment variable, and otherwise uses the current working directory for auto-detection. Note that setting Ansible's `DEFAULT_VAULT_IDENTITY_LIST` environment variable will override this behavior.

#### Encryption salts

Each time you edit a vault or otherwise encrypt a value, a randomly generated salt is used to avoid identical plain values resulting in identical ciphers. One side-effect of this is that each time a single encrypted variable is edited, all other ciphers in the vault will change as well, possibly making changelogs (e.g. from git) less useful. You can avoid this by passing a fixed salt via `--fixed-salt|-S <salt>` or the environment. Note that it should be at least 32 characters long and sufficiently random for Ansible's AES-256 encryption, and that you won't benefit from unique ciphers for identical plaintexts anymore.

### Diff logging

**TL;DR:** You can use `-l <log directory>` to log changes to edited vaults to a vault-encrypted log file.

You can automatically log any changes performed to a vault by the commands `create`, `edit`, `convert`, `set`, and `del` using the `--log|-l <log path>` or `--log-plain|-L <log path>` flags. The changes will be saved as a YAML-compatible diff with some additional metadata. When using `--log`, the entire log file is encrypted as a vault using your encryption key. This is important as the diffs contain the plain values of encrypted variables. When using `--log-plain` to skip encryption, make sure you're only editing fully plaintext variable files to avoid leaking secrets.

As you cannot mix different encryption keys and/or plain logging in the same log file, consider either using a dedicated logging key (`--logging-key <identifier>`) or specifying a directory as the log path (in which case `ansible-vars` automatically chooses a filename based on the used encryption key's identifier) if you frequently switch between keys.

### Examples

```sh
# Create the variable file `./host_vars/my_host/main.yml` without full encryption and open it for editing
ansible-vars create --make-parents --plain host_vars/my_host/main.yml
# Short version (see `Tips` section to learn about vault search paths)
ansible-vars create -mp h:my_host/

# Decrypt the vault file `./config/logging.yml` in-place
ansible-vars decrypt file config/logging.yml

# Recursively search vaults and variable files in `./host_vars` for left-over TODOs
ansible-vars grep '# TODO' h:

# Print a tree structure showing the differences between two versions of the vault `./vars/passwords.yml`
ansible-vars changes v:passwords.yml.old v:passwords.yml

# Create decrypted mirrors of the directories `./host_vars`, `./group_vars`, and `./vars` in `/tmp/decrypted`
ansible-vars file-daemon /tmp/decrypted

# Get the decrypted value of `<vault root>['my_key'][4]['133']` in `./group_vars/database_hosts/main.yml` as JSON
ansible-vars get --json g:database_hosts 'my_key' '[4]' '133'
```

### Tips

- When a command supports a `--json` flag, the command's help (`ansible-vars <command> -h`) will define the returned structure.
- The directories `host_vars`, `group_vars`, and `vars` are common vault locations. When in their parent directory, you can use the prefixes `h:`, `g:`, and `v:` in any vault path you specify, followed by a path relative to them. Wherever a directory is not expected as a path, supplying a directory path will also append a `main.yml` to the path automatically. In summary, this lets you type `h:my_host` when you actually mean `./host_vars/my_host/main.yml`. Shell completion for these prefixed paths is provided.
    - These three directories are also default sources for the `file-daemon` command.
    - For vault creation with the `--make-parents` flag, a path like `h:my_host` would be ambiguous as to the expanded path being `./host_vars/my_host` or `./host_vars/my_host/main.yml`, since the directory does not exist yet. `ansible-vars` will assume the first case, unless you end your search path with a / like `h:my_host/`.
- When referencing vault traversal keys, you can specify numbers to access lists and number-indexed dictionaries. However, just specifying `2` as a key segment will resolve into the string `'2'`. Instead, you should write `[2]` to mark it as a number index. If you need to specify the string `'[2]'` for some reason, you can escape it by adding another set of brackets (and so on).

### Commands

A brief overview of the available commands. You can change a lot of the default behavior described here using command flags. Use the command help to get additional information and available flags (`ansible-vars <command> -h`).

#### keyring

Displays the loaded vault secrets, including any auto-detected ones, along with their passphrase. Supports JSON output.

#### create

Creates a new vault or variable file. By default, full encryption is enabled to avoid accidentally leaking secrets. Use the `--plain|-p` flag to create a file with hybrid encryption, i.e. completely plain or with individually encrypted variables. After creating the file, it will open in edit mode (see `edit` command below).

#### edit

Opens a vault or variable file in the configured editor (`EDITOR` environment variable or passed using the `--edit-command|-e` flag) in decrypted form. Here, you can en-/decrypt, add, remove, and change variables. After saving the file and closing the editor, the file will be re-parsed and re-encrypted.

*Note: When choosing a custom edit command, make sure the command exits after the file is saved, as `ansible-vars` will read a finished command as the cue to start re-parsing the file contents.*

#### view

Prints the contents of a vault or variable file to the terminal, fully decrypted without any encryption markers. Supports JSON output.

#### info

Shows the amounts of encrypted and decrypted variables in a vault file. Supports JSON output.

#### encrypt, decrypt, is-encrypted

En-/Decrypts or checks the encryption status of a file or string value. Note that only full file encryption is considered in file mode, a hybrid vault with individually encrypted variables will be counted as plain.

#### rekey

Re-encrypts a vault file with a different encryption key and/or salt. The key specified in the global `--encryption-key|-K <identifier>` flag is used for encryption, along with an optional fixed salt set via the global `--fixed-salt|-S <salt>` flag.

#### convert

Convenience function to convert between fully encrypted vaults and hybrid vaults. Useful if you wish to convert your "legacy" fully encrypted vaults to plain files with all string values individually encrypted. Works both ways.

#### grep

Searches one or multiple vault(s) for matches on a pattern, either in their full text or limited to keys/values. Supports recursively searching directories and JSON output. Note that non-variable/-vault files are not included in the search.

#### diff

Compares two vaults or variable files and prints the line diff.

#### changes

Compares two vaults or variable files and prints a tree structure showing differences between their variables. Supports JSON output.

#### file-daemon

Starts a daemon which mirrors the decrypted contents of one or multiple vault or variable files/directories to a target directory. By default, this includes the directories `./host_vars`, `./group_vars`, and `./vars`. Changes to the source files are reflected in the decrypted targets. Changes to the target files are ignored. For added security, consider syncing the files to a mounted ramdisk.

#### get

Displays the (by default recursively decrypted) value of a specified key in a vault or variable file. Supports dictionary and list traversal, and JSON output.

#### set, del (experimental)

Creates, updates, or deletes a key-value pair from a vault or variable file. When setting a value, you may provide a YAML string which will be parsed into the corresponding objects. When the `--encrypt` flag is set, the object's leaf string values will be encrypted. Note that these are experimental features, as the current parser has difficulty preserving the metadata for programmatic variable changes. Comments and Jinja2 blocks between the affected key and the next key in the file may be lost.

### Environment variables

#### AV_SECRETS_ROOT (or ANSIBLE_HOME)

If this variable is set to a file or directory path, the program will use its value to auto-detect configured vault secrets if detection is not disabled via `--no-detect-keys|-D`. When a configuration file path is given, the file will be searched for a `vault_identity_list` and the corresponding secrets get loaded. When a directory path is given, `ansible-vars` will look for an `ansible.cfg` in that directory and perform the same loading procedure on that file. Note that setting Ansible's `DEFAULT_VAULT_IDENTITY_LIST` environment variable will skip this step entirely.

When running the script from somewhere else, this way vault secrets will be resolved as if you were in this directory or using this configuration file. When left unset, Ansible checks if a configuration file path is set via its standard environment variable, and otherwise uses the current working directory for auto-detection. It is equivalent to setting the `--detection-source` flag.

#### AV_RESOLVER_ROOT

If this variable is set, the program will use its value as the working directory. When running the script from somewhere else, this way paths will be resolved as if you were in this directory.

#### AV_COLOR_MODE

Set the color mode as you would with `-C <mode>`.

#### AV_TEMP_DIR

Set the tempfile/staging root as you would with `-T <path>`.

#### AV_CREATE_PLAIN

Invert the default creation mode for files: If unset or `no`, files are created with full encryption unless specified otherwise via the `--plain|-p` flag. This behavior mirrors that of `ansible-vault`. When set to `yes`, the behavior and flag are inverted as files are created without encryption by default unless specified otherwise via the `--no-plain|-P` flag.

#### AV_SALT

Set a fixed salt as you would with `-S <salt>`.

### Python library

When using `ansible-vars` as a library, import any of these modules from the `ansible_vars` module.

#### vault module

Contains the classes `Vault` and `VaultFile`. A `Vault` is initialized using the contents of a vault or variable file, while `VaultFile` wraps around a `Vault` instance and manages reading from and writing to a file directly. These are the main classes you'll likely use, as they contain the means of loading, manipulating and exporting vault and variable data. Both can also be initialized using an 'editable' (the output of `<vault>.as_editable()`, contains encryption markers and an optional explanatory comment header). A `vault_crypt.VaultKeyring` is required for en-/decryption operations.

`EncryptedVar` represents an encrypted value. The stored cipher can be decrypted using a `vault_crypt.VaultKey(ring)`. Will be dumped as `!vault`-tagged values on exporting.

`ProtoEncryptedVar` is used for parsing, as the `!enc` tag parses into such a proto-var and is then converted to an `EncryptedVar`, and vice-versa for exporting.

#### vault_crypt module

The `VaultKey` class represents a single vault secret, comprised of an identifier and an `ansible.parsing.vault.VaultSecret`. Can be initialized using a plain passphrase instead of a `VaultSecret` as well.

The `VaultKeyring` combines a collection of `VaultKey`s. It supports auto-detection of any secrets available in the present working directory (or a custom source) using the `ansible.cli` module, appending them to the `<keyring>.keys` collection. While all keys are tried in order for decryption operations, only one key can be used for encrypting data. This key is usually the first key in the `<keyring>.keys` collection, unless explicitly specified otherwise using `<keyring>.default_encryption_key` or passing a key to the `<keyring>.encrypt()` method.

#### util module

The `DiffLogger` with its wrapper `DiffFileLogger` generate log entries for changes to a vault and can save them to an encrypted or plain log file. A method decorator (`@<file logger>.log_changes(<vault used in wrapped method>)`) is available for your convenience.

The `VaultDaemon` syncs changes from a source file or directory to a target using the `watchdog` library, decrypting any vaults encountered on the way.

#### constants & errors modules

Custom types and exceptions, and static values. Mostly useful for type hints.

## Security considerations

When editing a file or creating a daemon, decrypted vaults are written to disk temporarily. The temporary files can only be accessed by the current user, but could potentially be restored through data recovery methods after deletion. To mitigate this issue, consider creating an in-RAM filesystem ("ramdisk") and using it as the staging directory (`--temp-dir <path>`) or the daemon target.

## Known issues and limitations

- YAML round-trip parser:
    - Trailing comments and Jinja2 blocks may be misaligned and a trailing newline may be inserted/removed when switching between folded (`|`, `>`) and non-foldes values.
    - The `set` and `del` commands may remove trailing comments and Jinja2 blocks.
    - Explicit start/end markers (`---`, `...`) are not preserved.
    - Supports lists, dictionaries, and scalar values.
    - Does not support custom YAML tags (`!tag`).
- Ansible:
    - Ansible only directly supports encrypted string values (although you can work around this with the `from_yaml` filter).
    - Ansible-encrypted strings must include a newline between the envelope and the cipher.
    - Ansible vault and variable file roots must be a dictionary.
        - Due to parsing limitations in `ansible-vars`, a file with explicit JSON style '{}' as the outermost level is currently not supported.
- `grep` command:
    - Will ignore files which cannot be parsed as an Ansible YAML file.
- `file-daemon` command:
    - Changes to file metadata (permissions, ...) are not mirrored.
- `ansible-vars` does not support files which are not (Jinja2) YAML dictionaries, except for limited support in these commands:
    - `edit`, `view` (without `--json` support), `encrypt`, `decrypt`, `is-encrypted`

## Extension plans

- I'm debating creating my own Jinja2 YAML round-trip parser to alleviate the metadata preservation issues of the current parser.
- I may add an Ansible action plugin for updating vault variables directly from an Ansible task (useful e.g. for automatically storing passwords that are set to a random value by Ansible). I am currently using a small script for this task.
- I want to create `ansible-vars` system packages for common repositories.
