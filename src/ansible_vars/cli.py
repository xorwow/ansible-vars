#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

# CLI entry point for ansible-vars

# Standard library imports
import os, re, sys, json, atexit, signal
from glob import glob
from time import sleep
from enum import StrEnum
from pathlib import Path
from shutil import rmtree
from builtins import print as std_print
from subprocess import run as sys_command
from tempfile import NamedTemporaryFile, gettempdir
from typing import Iterator, Type, Hashable, Callable, Any
from argparse import ArgumentParser, RawDescriptionHelpFormatter

# External library imports
import yaml
from argcomplete import autocomplete as shell_completion
from argcomplete.completers import FilesCompleter
from termcolor import colored
from pygments import highlight
from pygments.style import StyleMeta
from pygments.styles import get_style_by_name
from pygments.lexers.data import JsonLexer
from pygments.lexers.templates import YamlJinjaLexer
from pygments.formatter import Formatter
from pygments.formatters import TerminalFormatter, Terminal256Formatter, TerminalTrueColorFormatter

# Internal module imports
from .vault import VaultFile, EncryptedVar, ProtoEncryptedVar
from .vault_crypt import VaultKey, VaultKeyring
from .util import DiffFileLogger, VaultDaemon
from .constants import Unset, MatchLocation, SENTINEL_KEY
from .errors import YAMLFormatError, UnsupportedGenericFileOperation

## CLI argument parsing

HELP: dict[str, str] = {
    'epilog': '''
examples:

# Create a new encrypted vault in the current directory, using the first auto-detected vault key, and open it for editing
ansible-vars create my_vault.yml
# Edit a vault with a custom editor command (so it calls `nano -B <vault path>`)
ansible-vars edit --editor-command 'nano -B' my_vault.yml
# Encrypt a vars file in-place using a custom encryption key (by default, the first loaded key is used)
ansible-vars --add-key my_key '<passphrase>' --add-key other_key '<passphrase>' --encryption-key other_key encrypt my_vars.yml
# Check if a string value is encrypted (no keys need to be loaded for this)
ansible-vars is-encrypted string '<value>'
# Recursively search the directory `./host_vars` of vault files for decrypted text matches on a regex pattern
# `h:` is a shorthand for `./host_vars`, see tips section below for more information about advanced path resolution
ansible-vars grep '# TODO' h:
# Get the diff of two vaults
ansible-vars diff my_vault.yml.old my_vault.yml
# Get the decrypted value of a vault's key path `root['my_key'][0]['other_key']` as JSON
ansible-vars get my_vault.yml my_key '[0]' other_key
# Start a daemon which syncs the decrypted contents of all vault files in `./host_vars`, `./group_vars`, and `./vars` to a target directory
ansible-vars file-daemon /tmp/decrypted/

tips:

- Some commands allow for a `--json` flag. The individual help messages for these commands will specify the structure of their responses.
- For brevity, the term 'vault' is used in help messages to denote fully encrypted, partially encrypted and plain vars files.
- When a command asks for a vault file path it actually accepts multiple kinds of search path:
  - You can specify a full or relative path to a vault file just as usual. This path will always be tried first.
  - If you specify `h:<path>`, `g:<path>`, or `v:<path>`, it looks in `./host_vars`, `./group_vars`, or `./vars`, respectively.
  - If a resolved path is a directory instead of a file, it looks for or creates a `main.yml` in that directory.
  - For example, to open the file `/ansible/host_vars/my_host/main.yml`, you may run the command in `/ansible` and specify `h:my_host`.
  - For vault creation with the `--make-parents` flag, `<path>` will create the file `<path>`, while `<path>/` will create `<path>/main.yml`.
- Data keys are split into segments (e.g. `root['my_key'][0]` would become `'my_key', 0`) for easier parsing.
    - When specifying a key segment which is a number (e.g. a list index), surround it in brackets (`[2]`) to differentiate it from a string.
    - If you need to actually use the string `[2]`, add a set of brackets to escape it (`[[2]]` -> `'[2]'`, `[[[2]]]` -> `'[[2]]'`, ...).
- Each vault key may hold some metadata about upcoming comments and Jinja2 blocks. Beware, using `set` and `del` may delete this data.
''',
    'key_args': '''
Specify vault keys to load for en-/decryption. Not required for vars files with no encrypted variables.
A key is a combination of an identifier (can be a vault ID or anything else, ideally unique) and a passphrase.
By default, available keys are auto-detected if your current directory contains an Ansible config and appended to the ones you supplied.
If no explicit encryption key is specified, the first supplied/available key is used.

[!] When editing a hybrid vault file, changing even a single variable will change all variables' ciphers, as salts are generated randomly.
You can prevent this by passing a fixed salt via `-S <salt>`, which will result in any plaintext always resolving to the same cipher.
For Ansible's AES-256, a length of at least 32 characters is recommended.
''',
    'log_args': '''
Log a diff of any vault changes performed with this program to an encrypted or plain logfile, creating it if necessary.
If in encrypted mode, the supplied (-K) or inferred encryption key is used by default. It must match the existing logfile's key.
If a directory is supplied, the logfile name is generated from the encryption key's identifier.

Diff logging is supported for the commands `create`, `edit`, `convert`, `set`, and `del`.

[!] Beware that logging changes in an encrypted vault to a plain logfile may cause secrets leakage, as diffs are in decrypted form.
''',
    'cmd_keyring': '''
Show all vault keys that have been loaded by argument or auto-detection, as well as their passphrases.

JSON mode formatting:
- { <vault key identifier>: <passphrase>, ... }
- `--keys-only`: [ <vault key identifier>, ... ]
''',
    'cmd_create': '''
Create a new vault file, encrypting it with the encryption key, or a plain vars file. Then open it for editing.
If you specify a custom edit command, it must block until the editing is done. Note that the passed path is not the original vault path.
''',
    'cmd_edit': '''
Open a vault file for editing. Encrypted vars are specially marked and can be changed, created or removed.
If you specify a custom edit command, it must block until the editing is done. Note that the passed path is not the original vault path.
''',
    'cmd_view': '''
Show a vault's contents with all values in decrypted form, or as a JSON object holding just the data.

JSON mode formatting:
- { <key segment>: <dict|list|value>, ... } (basically YAML -> JSON conversion with node decryption)
- Could also be a list, but Ansible expects a dictionary as the data's baseline.
''',
    'cmd_info': '''
Show details about the encryption status of a vault's leaf values.

JSON mode formatting:
- { "full_encryption": <bool>, "encrypted_leaves": [ [ <key segment>, ... ], ... ], "plain_leaves": [ [ <key segment>, ... ], ... ] }
''',
    'cmd_encrypt': '''
Encrypt a string and return it or fully encrypt a file in-place. This uses the configured encryption key.
''',
    'cmd_decrypt': '''
Decrypt a string and return it or fully decrypt a file in-place. Uses the first matching one of the loaded keys.
''',
    'cmd_is_enc': '''
Check if a string or file is (fully) vault-encrypted.
''',
    'cmd_rekey': '''
Update a vault's ciphers with a new encryption key and/or salt.
The key referenced by `--encryption-key|-K <identifier>` and/or the salt set by `--fixed-salt|-S <salt>` are used for re-encryption.
''',
    'cmd_convert': '''
Switch a file between full outer and full inner encryption for convenient migrating between encryption schemes.
If the file is already fully encrypted, decrypt it in-place and encrypt all leaf values individually.
If the file is not fully encrypted, encrypt it in-place and decrypt all leaf nodes individually.
''',
    'cmd_grep': '''
Search one or multiple decrypted vault file(s) for text matches on a regex pattern. Returns matched text and locations.
By default, the locations are relative to the line and column numbers of the `edit` command's format, not the `view` one's.
You can also search only keys or only leaf values, in which case the matching keys and values are returned.
By default, all specified directory paths are searched recursively and all contained Ansible YAML files are matched with the pattern.
For non-regex queries, the search is case-insensitive.

JSON mode formatting:
- { <file path>: [ { "value": <matched string>, "context": [ <line>, ...], "start": [ <start line>, <start col> ], "end": [ <end line>, <end col> ] }, ... ], ... }
- `context` contains the full lines that were matched
- `--keys-only`, `--values-only`: { <file path>: [ { "key": [ <key segment>, ... ], "value": <value> }, ... ], ... }
''',
    'cmd_diff': '''
Compare two versions of a vault (or two entirely different ones) and show the diff with some additional context lines.
The diff is based on the decrypted/editable vault format.
''',
    'cmd_changes': '''
Compare two versions of a vault (or two entirely different ones) and show the differences in their nodes as a tree structure.
Removed nodes are colored red and marked with a `(-)`, added nodes green and marked with a `(+)`,
changed nodes blue and marked with a `(~)`, and nodes which were previously encrypted but aren't anymore orange and marked with a `(!)`.

JSON mode formatting:
- { "added": [ [ <key segment>, ... ], ... ], "removed": <like added>, "changed": <like added>, "decrypted": <like added> }
- Only minimal paths are included (e.g. after changing `root['my_key']['subkey']` and `root['my_key']['other_subkey']`, only `my_key` is included).
''',
    'cmd_daemon': '''
Creates a temporary directory at the target root directory path and syncs the selected source vaults and vault directories into the target in decrypted form.
Each added source file or directory is described by its vault path and a relative target path within the target root directory.
By default, the `./host_vars`, `./group_vars`, and `./vars` directories are automatically included if they exist.
Two sources can not have the same relative target path, i.e. directory merging is not supported.
Changes in the source(s) are synced to the target(s), including creating/removing/editing/moving files, but not the other way around.
The sync works as long as the command is running, after which the target root directory is deleted.

[!] On exit, all files in the target are deleted. They are not synced back to the source, so don't create or modify anything (important) in there.
[!] Updated file metadata is not copied to the target on modification, only the file contents.
''',
    'cmd_get': '''
Looks up the value of a key in a vault and displays it if it exists.
The value will be shown in (recursively) decrypted form.

JSON mode formatting:
- [ ... ] or { ... } for lists/dictionaries, "<value>" for strings, <value> for numbers
''',
    'cmd_set': '''
Creates or updates a node in a vault with a YAML value, optionally encrypting the value('s string leaves) first using the configured encryption key.
For creating a new list entry, the last specified key segment has to equal the largest index of the list plus one (e.g. `[5]` for a list of length 5).
The value is interpreted as YAML code.

[!] Creating new nodes or changing non-leaf nodes may break/remove trailing comments and Jinja2 blocks.
''',
    'cmd_del': '''
Deletes a node from a vault if it exists.

[!] Deleting nodes may break/remove trailing comments and Jinja2 blocks.
'''
}

# Not using defaults directly because we also want to ignore empty values
DEFAULT_EDITOR: str = os.environ.get('EDITOR', None) or ('notepad.exe' if os.name == 'nt' else 'vi')
DEFAULT_COLOR_MODE: str = os.environ.get('AV_COLOR_MODE', None) or ('256' if sys.stdout.isatty() else 'none')
DEFAULT_TEMP_DIR: str = os.environ.get('AV_TEMP_DIR', None) or gettempdir()
DEFAULT_CREATE_PLAIN: bool = (os.environ.get('AV_CREATE_PLAIN', None) or 'no').lower() in [ 'yes', 'y', 'true', 't', '1' ]
DEFAULT_SALT: str | None = os.environ.get('AV_SALT', None) or None
DEFAULT_SECRETS_ROOT: str | None = os.environ.get('AV_SECRETS_ROOT', None) or os.environ.get('ANSIBLE_HOME', None) or None
DEFAULT_RESOLVER_ROOT: str | None = os.environ.get('AV_RESOLVER_ROOT', None) or None

# Resolve all paths as if the caller is in the resolver root
if DEFAULT_RESOLVER_ROOT:
    os.chdir(DEFAULT_RESOLVER_ROOT)

args: ArgumentParser = ArgumentParser(
    prog = 'ansible-vars',
    epilog = HELP['epilog'],
    formatter_class = RawDescriptionHelpFormatter,
    description = 'View and manipulate Ansible vars and vault files. Use `ansible-vars <command> -h` to get detailed help.'
)

# Custom shell completion for prefixed paths
def _prefixed_path_completer(prefix: str, **_) -> list[str]:
    has_prefix: bool = len(prefix) > 1 and prefix[:2] in ( 'h:', 'g:', 'v:' )
    resolved_prefix: str | None = { 'h:': 'host_vars', 'g:': 'group_vars', 'v:': 'vars' }[prefix[:2]] if has_prefix else None
    if resolved_prefix and os.path.isdir(os.path.abspath(resolved_prefix)):
        # Replace prefix with actual path
        path_prefix: str = prefix[:3] if (len(prefix) > 2 and prefix[2] == os.path.sep) else prefix[:2]
        new_prefix: str = os.path.join(resolved_prefix, prefix[len(path_prefix):])
        # Use FilesCompleter to get completions in the resolved directory
        completions: list[str] = FilesCompleter()(new_prefix)
        # Adjust the completions to keep the prefix
        return [
            f"{ path_prefix }{ os.path.relpath(completion, resolved_prefix) }{ os.path.sep * os.path.isdir(completion) }"
            for completion in completions 
        ]
    else:
        return FilesCompleter()(prefix)

# Base args

args.add_argument('--debug', '-d', action='store_true', help='print debug information')
args.add_argument(
    '--color-mode', '-C', type=str, choices=['none', 'basic', '256', 'truecolor'], default=DEFAULT_COLOR_MODE,
    help=f"set terminal color capability (default: { DEFAULT_COLOR_MODE })"
)
args.add_argument(
    '--temp-dir', '-T', type=str, metavar='<path>', default=DEFAULT_TEMP_DIR,
    help=f"use this directory for vault staging instead of the system\'s TMP directory (default: { DEFAULT_TEMP_DIR })"
)

key_args = args.add_argument_group('vault key management', description=HELP['key_args'])
# This arg can be repeated (results in [ [id, passphrase], ... ])
key_args.add_argument(
    '--add-key', '-k', type=str, nargs=2, action='append', dest='keys', default=[], metavar=('<identifier>', '<passphrase>'), help='add a vault key'
)
key_mutex = key_args.add_mutually_exclusive_group()
key_mutex.add_argument('--no-detect-keys', '-D', action='store_false', dest='detect_keys', help='disable automatic key detection')
key_mutex.add_argument(
    '--detection-source', type=str, metavar='<secrets root>', default=DEFAULT_SECRETS_ROOT,
    help=f"use this directory or config file to detect keys (default: { DEFAULT_SECRETS_ROOT or 'CWD' })"
)
key_args.add_argument('--encryption-key', '-K', type=str, metavar='<identifier>', help='which of the loaded keys to use for encryption')
key_args.add_argument(
    '--fixed-salt', '-S', type=str, metavar='<salt>', default=DEFAULT_SALT,
    help='a fixed salt to use for encryption (should be 32+ chars!)'
)

log_args = args.add_argument_group('logging vault changes', description=HELP['log_args'])
log_mutex = log_args.add_mutually_exclusive_group()
log_mutex.add_argument('--log', '-l', type=str, metavar='<log path>', help='log to an encrypted logfile (uses the encryption key)')
log_mutex.add_argument('--log-plain', '-L', type=str, metavar='<log path>', help='log to a plain logfile (dangerous!)')
log_args.add_argument('--logging-key', '-Q', type=str, metavar='<identifier>', help='use this loaded key for logging instead of the encryption key')

# Commands
commands = args.add_subparsers(dest='command', metavar='<command>', required=True)

cmd_keyring = commands.add_parser(
    'keyring', help='show available vault keys and their passphrases', description=HELP['cmd_keyring'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_keyring.add_argument('--json', '-j', action='store_true', dest='as_json', help='print the vault keys as JSON and nothing else')
cmd_keyring.add_argument('--keys-only', '-o', action='store_false', dest='show_passphrases', help='show only the vault keys, not the passphrases')

cmd_create = commands.add_parser(
    'create', help=f"create a new vault ({ 'hybrid/plain' if DEFAULT_CREATE_PLAIN else 'fully encrypted' } by default)",
    description=HELP['cmd_create'], formatter_class=RawDescriptionHelpFormatter
)
cmd_create.add_argument('vault_path', type=str, metavar='<vault path>', help='path to create a new vault at') \
    .completer = _prefixed_path_completer # type: ignore
# Invert flag if the user wants plain mode by default
if DEFAULT_CREATE_PLAIN:
    cmd_create.add_argument('--no-plain', '-P', action='store_true', dest='encrypt_vault', help='create with full file encryption')
else:
    cmd_create.add_argument('--plain', '-p', action='store_false', dest='encrypt_vault', help='create without full file encryption')
cmd_create.add_argument('--make-parents', '-m', action='store_true', help='create all directories in the given path')
create_mutex = cmd_create.add_mutually_exclusive_group()
create_mutex.add_argument('--no-edit', '-n', action='store_false', dest='open_edit_mode', help='just create the file, don\'t open it for editing')
create_mutex.add_argument(
    '--edit-command', '-e', type=str, default=DEFAULT_EDITOR, help=f"editor command to use (runs as <command> <some path>) (default: { DEFAULT_EDITOR })"
)

cmd_edit = commands.add_parser(
    'edit', help='edit a vault', description=HELP['cmd_edit'], formatter_class=RawDescriptionHelpFormatter
)
cmd_edit.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to edit') \
    .completer = _prefixed_path_completer # type: ignore
cmd_edit.add_argument(
    '--edit-command', '-e', type=str, default=DEFAULT_EDITOR, help=f"editor command to use (runs as <command> <some path>) (default: { DEFAULT_EDITOR })"
)

cmd_view = commands.add_parser(
    'view', help='show the decrypted contents of a vault', formatter_class=RawDescriptionHelpFormatter
)
cmd_view.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to dump') \
    .completer = _prefixed_path_completer # type: ignore
cmd_view.add_argument('--json', '-j', action='store_true', dest='as_json', help='print the vault data as JSON and nothing else')

cmd_info = commands.add_parser(
    'info', help='show information about a vault\'s variables', description=HELP['cmd_info'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_info.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to analyze') \
    .completer = _prefixed_path_completer # type: ignore
cmd_info.add_argument('--json', '-j', action='store_true', dest='as_json', help='print the information as JSON and nothing else')

cmd_encrypt = commands.add_parser(
    'encrypt', help='encrypt a file in-place or a string with the encryption key', description=HELP['cmd_encrypt'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_encrypt.add_argument('target_type', type=str, choices=['file', 'string'], help='select if target is a file path or a string')
cmd_encrypt.add_argument('target', type=str, metavar='<vault path | string>', help='path of vault or string value to encrypt') \
    .completer = _prefixed_path_completer # type: ignore
cmd_encrypt.add_argument('--quiet', '-q', action='store_true', help='only output the encrypted value (ignored in file mode)')

cmd_decrypt = commands.add_parser(
    'decrypt', help='decrypt a file in-place or a string', description=HELP['cmd_decrypt'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_decrypt.add_argument('target_type', type=str, choices=['file', 'string'], help='select if target is a file path or a string')
cmd_decrypt.add_argument('target', type=str, metavar='<vault path | string>', help='path of vault or string value to decrypt') \
    .completer = _prefixed_path_completer # type: ignore
cmd_decrypt.add_argument('--quiet', '-q', action='store_true', help='only output the decrypted value (ignored in file mode)')

cmd_is_enc = commands.add_parser(
    'is-encrypted', help='check if a file or string is vault-encrypted', description=HELP['cmd_is_enc'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_is_enc.add_argument('target_type', type=str, choices=['file', 'string'], help='select if target is a file path or a string')
cmd_is_enc.add_argument('target', type=str, metavar='<vault path | string>', help='path of vault or string value to check') \
    .completer = _prefixed_path_completer # type: ignore
cmd_is_enc.add_argument('--quiet', '-q', action='store_true', help='no output, only set the rc to 0 if encrypted or 100 if unencrypted')

cmd_rekey = commands.add_parser(
    'rekey', help='update a vault\'s encryption key (from -K) and/or salt (from -S)', description=HELP['cmd_rekey'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_rekey.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to rekey') \
    .completer = _prefixed_path_completer # type: ignore

cmd_convert = commands.add_parser(
    'convert', help='switch vault between outer (file) and inner (vars) encryption', description=HELP['cmd_convert'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_convert.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to convert') \
    .completer = _prefixed_path_completer # type: ignore

cmd_grep = commands.add_parser(
    'grep', help='search a file or folder for a pattern', description=HELP['cmd_grep'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_grep.add_argument('query', type=str, metavar='<pattern>', help='regex query to match with targets')
cmd_grep.add_argument('targets', type=str, nargs='+', metavar='[<target> ...]', help='file(s) or folder(s) to search recursively') \
    .completer = _prefixed_path_completer # type: ignore
cmd_grep.add_argument('--no-recurse', '-n', action='store_false', dest='recurse', help='don\'t recurse into target folders\' subfolders')
grep_mutex_limit = cmd_grep.add_mutually_exclusive_group()
grep_mutex_limit.add_argument('--keys-only', '-o', action='store_const', const='keys', dest='limit_grep', help='only search vault data\'s key names')
grep_mutex_limit.add_argument('--values-only', '-O', action='store_const', const='values', dest='limit_grep', help='only search vault data\'s leaf values')
grep_mutex_limit.add_argument('--plain-format', '-p', action='store_true', help='show match locations relative to the `view` command\'s output, not `edit`')
grep_mutex_type = cmd_grep.add_mutually_exclusive_group()
grep_mutex_type.add_argument('--simple', '-s', action='store_false', dest='is_regex', help='mark that the query is not a regex, but plain text')
grep_mutex_type.add_argument('--multiline', '-m', action='store_true', help='make . in a regex pattern match newlines')
cmd_grep.add_argument('--json', '-j', action='store_true', dest='as_json', help='print the matches as JSON and nothing else')
cmd_grep.add_argument('--quiet', '-q', action='store_true', help='no output, only set the rc to 0 if any matches found or 100 if none found')

cmd_diff = commands.add_parser(
    'diff', help='show line differences between two vaults', description=HELP['cmd_diff'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_diff.add_argument('old_vault', type=str, metavar='<old vault vault path>', help='path of "old"/base vault') \
    .completer = _prefixed_path_completer # type: ignore
cmd_diff.add_argument('new_vault', type=str, metavar='<new vault vault path>', help='path of "new"/changed vault') \
    .completer = _prefixed_path_completer # type: ignore
cmd_diff.add_argument('--context-lines', '-c', type=int, metavar='<amount>', default=3, help='show <amount> lines of context around changed lines (default: 3)')

cmd_changes = commands.add_parser(
    'changes', help='show var changes between vaults', description=HELP['cmd_changes'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_changes.add_argument('old_vault', type=str, metavar='<old vault vault path>', help='path of "old"/base vault') \
    .completer = _prefixed_path_completer # type: ignore
cmd_changes.add_argument('new_vault', type=str, metavar='<new vault vault path>', help='path of "new"/changed vault') \
    .completer = _prefixed_path_completer # type: ignore
cmd_changes.add_argument('--json', '-j', action='store_true', dest='as_json', help='print added/changed/removed/decrypted vars as JSON and nothing else')

cmd_daemon = commands.add_parser(
    'file-daemon', help='sync decrypted vault copies into a folder', description=HELP['cmd_daemon'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_daemon.add_argument('target_root', type=str, metavar='<target root path>', help='root folder the decrypted files and folders should be synced into (non-existent or empty)') \
    .completer = _prefixed_path_completer # type: ignore
# This arg can be repeated (results in [ [source, rel_target], ... ])
cmd_daemon.add_argument(
    '--add-source', '-s', type=str, nargs=2, action='append', dest='sources', default=[], metavar=('<source path>', '<target subpath>'),
    help='vault file or folder to sync and rel. path in <target root> to sync into'
).completer = _prefixed_path_completer # type: ignore
cmd_daemon.add_argument('--no-recurse', '-n', action='store_false', dest='recurse', help='don\'t recurse into source folders\' subfolders')
cmd_daemon.add_argument('--no-default-dirs', '-N', action='store_false', dest='include_default_dirs', help='don\'t include default sync sources')
cmd_daemon.add_argument('--force', '-f', action='store_true', help='if the target root already exists and is not empty, delete its contents')

cmd_get = commands.add_parser(
    'get', help='get a key\'s (recursively decrypted) value if it exists', description=HELP['cmd_get'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_get.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to get value from') \
    .completer = _prefixed_path_completer # type: ignore
cmd_get.add_argument('key_segments', type=str, nargs='+', metavar='<key segment> [<key segment> ...]', help='segment(s) of the key to look up (`[<num>]` for numbers)')
cmd_get.add_argument('--no-decrypt', '-n', action='store_false', dest='decrypt_value', help='don\'t decrypt the value if it is encrypted')
get_mutex_format = cmd_get.add_mutually_exclusive_group()
get_mutex_format.add_argument('--quiet', '-q', action='store_true', help='only output the raw YAML value or set the rc to 100 if the key doesn\'t exist')
get_mutex_format.add_argument('--json', '-j', action='store_true', dest='as_json', help='print the value as JSON or set the rc to 100 if the key doesn\'t exist')

cmd_set = commands.add_parser(
    'set', help='update a key\'s value or add a new key (experimental!)', description=HELP['cmd_set'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_set.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to set value in') \
    .completer = _prefixed_path_completer # type: ignore
cmd_set.add_argument('value', type=str, metavar='<value>', help='value to set (will be loaded as YAML)')
cmd_set.add_argument('key_segments', type=str, nargs='+', metavar='<key segment> [<key segment> ...]', help='segment(s) of the key to look up (`[<num>]` for numbers)')
cmd_set.add_argument('--encrypt', '-e', action='store_true', dest='encrypt_value', help='recursively encrypt the value(\'s leaves) if it is\'t encrypted yet')

cmd_del = commands.add_parser(
    'del', help='delete a key and its value if they exist (experimental!)', description=HELP['cmd_del'],
    formatter_class=RawDescriptionHelpFormatter
)
cmd_del.add_argument('vault_path', type=str, metavar='<vault path>', help='path of vault to delete key from') \
    .completer = _prefixed_path_completer # type: ignore
cmd_del.add_argument('key_segments', type=str, nargs='+', metavar='<key segment> [<key segment> ...]', help='segment(s) of the key to look up (`[<num>]` for numbers)')
cmd_del.add_argument('--quiet', '-q', action='store_true', help='no output, only set the rc to 0 if the key exists or 100 if it doesn\'t')

shell_completion(args)
config = args.parse_args()

## CLI helpers

# Terminal output

class Color(StrEnum):
    '''Available terminal message colors.'''
    # Basic output
    DEBUG = 'blue'
    INFO = 'light_cyan'
    GOOD = 'light_green'
    MEH  = 'light_yellow'
    BAD  = 'light_red'
    # Changes command tree colors
    TREE_TITLE = 'magenta'
    TREE_ADDED = 'light_green'
    TREE_REMOVED = 'light_red'
    TREE_CHANGED = 'light_cyan'
    TREE_DECRYPTED = 'light_yellow'
    TREE_UNCHANGED = 'white'

# Overwrite standard print function with color support
def print(msg: Any, color: Color = Color.INFO, **print_args) -> None:
    '''Outputs text to the console, coloring it if `color` is set to True in this module.'''
    msg = colored(str(msg), color=color.value) if config.color_mode != 'none' else str(msg) # type: ignore
    std_print(msg, **print_args)

def debug(msg: Any, prefix: str = '(debug) ', **print_args) -> None:
    '''Outputs a debug message with a prefix.'''
    if config.debug:
        print(prefix + str(msg), Color.DEBUG, **print_args)

# All available color palettes are available in pygments.styles.STYLE_MAP
# These look nice in 256/truecolor (they're all the same in basic mode):
# zenburn solarized-light solarized-dark paraiso-dark one-dark nord monokai material lightbulb friendly_grayscale
# zenburn has the best differentiation between token types while still having good contrast and readability
highlight_style: StyleMeta = get_style_by_name(os.environ.get('ANSIBLE_VARS_THEME', 'zenburn'))

json_highlight_lexer = JsonLexer(stripall=True)
yaml_highlight_lexer = YamlJinjaLexer(stripall=True)
if config.color_mode != 'none':
    _formatter: Type[Formatter] = { 'basic': TerminalFormatter, '256': Terminal256Formatter, 'truecolor': TerminalTrueColorFormatter }[config.color_mode]
    highlight_formatter: Formatter = _formatter(linenos=False, cssclass="source", style=highlight_style)

def print_json(code: str) -> None:
    '''Print JSON code with syntax highlighting if a `color_mode` is available.'''
    if config.color_mode == 'none':
        return std_print(code)
    std_print(highlight(code, json_highlight_lexer, highlight_formatter).strip('\n'))

def print_yaml(code: str) -> None:
    '''Print Jinja2 YAML code with syntax highlighting if a `color_mode` is available.'''
    if config.color_mode == 'none':
        return std_print(code)
    std_print(highlight(code, yaml_highlight_lexer, highlight_formatter).strip('\n'))

def print_diff(diff: str) -> None:
    '''Print a diff with highlighting if a `color_mode` is available.'''
    _color_map: dict = { '-': Color.TREE_REMOVED, '+': Color.TREE_ADDED, '@': Color.INFO, '*': Color.TREE_UNCHANGED }
    for line in diff.split('\n'):
        color: Color = _color_map[line[0]] if (len(line) > 0 and line[0] in [ '-', '+', '@' ]) else _color_map['*']
        print(line, color)

def resolve_key_path(segments: list[str]) -> tuple[Hashable, ...]:
    '''
    Resolves a list of string key segments into the correct types.
    Numbers should be represented as `[<number>]`, which can be escaped by adding brackets (`[[2]]` -> `'[2]'`, ...).
    '''
    resolved: list[Hashable] = []
    for segment in segments:
        # Check if it's a number or an escaped number-like string (2 -> '2', '[2]' -> 2, '[[2]]' -> '[2]', ...)
        pattern: str = r'^\[+([+-]?((\d+(\.\d*)?)|(\.\d+))([eE][-+]?\d+)?)\]+$'
        match: re.Match[str] | None = re.match(pattern, segment)
        opening_brackets: int = len(segment) - len(segment.lstrip('['))
        closing_brackets: int = len(segment) - len(segment.rstrip(']'))
        if match and opening_brackets == closing_brackets:
            number_str: str = match.group(1)
            # Convert to number if only one pair of brackets
            if opening_brackets == 1:
                number: float | int = float(number_str)
                if number.is_integer():
                    number = int(number)
                resolved.append(number)
            # Remove a pair of brackets and keep as string
            else:
                resolved.append(segment[1:-1])
        # Simple string
        else:
            resolved.append(segment)
    return tuple(resolved)

def format_key_path(key_path: tuple[Hashable, ...]) -> str:
    '''Formats a traversal path into a string representation.'''
    def _represent(value) -> str:
        return f"'{ value }'" if type(value) is str else str(value)
    return ' -> '.join(map(_represent, key_path))

# Vault path loader

def resolve_vault_path(search_path: str, create_mode: bool = False, allow_dirs: bool = False) -> str:
    '''
    Resolve the path to a (vault) file or optionally a directory.
    The given search path is tested for these cases in order:
    - As an absolute path or a relative path from the PWD
    - As a relative path with prefix `h:` / `g:` / `v:` to be treated as a subpath into `./host_vars` / `./group_vars` / `./vars`
    - If the path is expected to be a file and the previous steps found a directory, append a `main.yml` to that path
    If `create_mode` is set to True (i.e. the searched file doesn't exist yet), we test for case 2 first, then cases 1 and 3.
    Setting `create_mode` will also treat a path ending in a / as a folder to create a `main.yml` in.
    '''
    # Try the path as-is first
    abspath: str = os.path.abspath(search_path)
    if not os.path.exists(abspath) or (not allow_dirs and os.path.isdir(abspath)):
        # Check for prefix search notation
        if len(search_path) > 1 and search_path[1] == ':' and (prefix := search_path[0]) in [ 'h', 'g', 'v' ]:
            resolved: dict = { 'h': 'host_vars', 'g': 'group_vars', 'v': 'vars' }
            abspath = os.path.abspath(resolved[prefix])
            if len(search_path) > 2:
                abspath = os.path.join(abspath, search_path[2:].lstrip(os.path.sep))
    # Check for main.yml in directory
    if (not allow_dirs and os.path.isdir(abspath)) or (create_mode and search_path.endswith('/')):
        abspath = os.path.join(abspath, 'main.yml')
    # Debug output
    debug(f"Resolved path { search_path } to { abspath }")
    # If we're in creation mode, we can't known if the file exists yet, so we check prefix notation first
    if create_mode:
        return abspath
    if not os.path.exists(abspath):
        raise FileNotFoundError(f"Could not resolve vault path { abspath }")
    return abspath

## CLI logic

# Print all exceptions unless we're in debug mode
def _exc_hook(exctype, value, traceback) -> None:
    if config.debug:
        sys.__excepthook__(exctype, value, traceback)
    else:
        print(f"{ value.__class__.__name__ }: { value }", Color.BAD)
        print('Use --debug to get the full stacktrace')
sys.excepthook = _exc_hook

# Load vault keys

_explicit_keys: list[VaultKey] = [ VaultKey(passphrase, vault_id=id) for id, passphrase in config.keys ]
keyring: VaultKeyring = VaultKeyring(
    _explicit_keys.copy(), default_salt=config.fixed_salt,
    detect_available_keys=config.detect_keys, detection_source=config.detection_source
)

if config.encryption_key:
    keyring.default_encryption_key = keyring.key_by_id(config.encryption_key)

debug(f"Loaded { len(keyring.keys) } vault key(s): { keyring }")
try:
    debug(f"Encryption key: { keyring.encryption_key.id }")
except:
    debug('Encryption key: unavailable')
if config.fixed_salt:
    debug(f"Using fixed encryption salt: { config.fixed_salt }")

# Set up logging

_log_path: str = getattr(config, 'log', None) or getattr(config, 'log_plain', None) or '/dev/null'
log_enabled: bool = bool((getattr(config, 'log', None) or getattr(config, 'log_plain', None)))
_log_plain: bool = bool(getattr(config, 'log_plain', None) or not log_enabled)
_log_key: VaultKey | VaultKeyring | None = None if _log_plain else (keyring.key_by_id(config.logging_key) if config.logging_key else keyring)
logger = DiffFileLogger(_log_path, _log_key, plain=_log_plain)

# Keyring command

if config.command == 'keyring':
    # Passphrase helper
    def _passphrase_from_key(key: VaultKey, quote: bool = True) -> str:
        return ("'" * quote + key.passphrase + "'" * quote) if key.passphrase else 'passphrase unknown'
    # Normal output format
    if not config.as_json:
        # Formats a list of keys into a list of entry lines
        def _format_key_list(key_list: list[VaultKey]) -> Iterator[str]:
            for key in key_list:
                yield f"- { key.id }" + (f": { _passphrase_from_key(key) }" * config.show_passphrases)
        # Show keys loaded from args
        print('Explicitly loaded keys:', Color.GOOD)
        if _explicit_keys:
            print('\n'.join(_format_key_list(_explicit_keys)))
        else:
            print('No keys loaded')
        # Show keys loaded by auto-detection
        print('\nAuto-detected keys:', Color.GOOD)
        if config.detect_keys:
            detected_keys: list[VaultKey] = keyring.keys[len(_explicit_keys):]
            if detected_keys:
                print('\n'.join(_format_key_list(detected_keys)))
            else:
                print('No keys detected.')
        else:
            print('Function disabled by flag', Color.MEH)
    # JSON mode with passphrases
    elif config.show_passphrases:
        print_json(json.dumps({ key.id: _passphrase_from_key(key, quote=False) for key in keyring.keys }, indent=2))
    # JSON mode without passphrases
    else:
        print_json(json.dumps([ key.id for key in keyring.keys ]))

# Create & Edit commands

if config.command in [ 'create', 'edit' ]:
    # Create or load vault file
    vault_path: str = resolve_vault_path(config.vault_path, create_mode=(config.command == 'create'))
    if config.command == 'create':
        if config.make_parents:
            os.makedirs(os.path.dirname(vault_path), mode=0o700, exist_ok=True)
            if not vault_path.endswith('.yml'):
                print(f"Treating path as a file, append a / to create a directory containing a main.yml instead", Color.MEH)
        vault = VaultFile.create(vault_path, full_encryption=config.encrypt_vault, permissions=0o600, keyring=keyring)
        print(f"Created { 'encrypted' if vault.full_encryption else 'plain' } vault at { vault_path }", Color.GOOD)
    else:
        try:
            vault = VaultFile(vault_path, keyring=keyring)
        except YAMLFormatError:
            print('Invalid vault format, will be treated as a generic file', Color.MEH)
            with NamedTemporaryFile(mode='w+', dir=config.temp_dir, prefix='vaultlike_') as edit_file:
                with open(vault_path, 'r+') as file:
                    # Load and decrypt file
                    content: str = file.read()
                    if (is_enc := VaultKey.is_encrypted(content)):
                        content = keyring.decrypt(content)
                    # Let user edit the content in a temporary file
                    edit_file.write(content)
                    edit_file.flush()
                    sys_command(f"{ config.edit_command } { edit_file.name }", shell=True)
                    edit_file.seek(0)
                    # Encrypt the new content and write it back
                    new_content: str = edit_file.read()
                    if is_enc:
                        new_content = keyring.encrypt(new_content)
                    file.seek(0)
                    file.truncate()
                    file.write(new_content)
                    print(f"Saved changes!", Color.GOOD)
            exit()
    # Open vault for edit mode
    if getattr(config, 'open_edit_mode', True):
        print(f"Editing vault at { vault_path }")
        # Create a secure temporary file to host the editable content
        with NamedTemporaryFile(mode='w+', dir=config.temp_dir, prefix='vault_', suffix='.yml') as edit_file:
            # Write vault contents to temp file
            editable: str = vault.as_editable()
            edit_file.write(editable)
            edit_file.flush()
            while True:
                # Open editor and wait for it to close
                edit_file.seek(0)
                sys_command(f"{ config.edit_command } { edit_file.name }", shell=True)
                # Re-load vault from edited content and save to original location
                edit_file.seek(0)
                new_editable: str = edit_file.read()
                if editable != new_editable:
                    try:
                        new_vault: VaultFile = VaultFile.from_editable(vault, new_editable)
                    except YAMLFormatError as e:
                        print('Invalid YAML format:', Color.BAD)
                        print(e.parent if e.parent else e, Color.BAD)
                        print('Note that Ansible YAML must have a dictionary as a root.', Color.BAD)
                        decision: str = input(colored('Continue editing? (discard changes on no) [Yn] > ', Color.MEH.value))
                        if decision.strip().lower() not in [ 'n', 'no' ]:
                            continue
                        else:
                            print('Changes discarded.', Color.BAD)
                            break
                    new_vault.save()
                    print(f"Saved changes!", Color.GOOD)
                    decrypted_vars:   list[tuple[Hashable, ...]] = []
                    new_plain_leaves: list[tuple[Hashable, ...]] = []
                    def _find_new_plain_vars(path: tuple[Hashable, ...], value: Any) -> Any:
                        if path != ( SENTINEL_KEY, ) and type(value) is not EncryptedVar:
                            if (old_value := vault.get(path, default=Unset)) != value:
                                if type(old_value) is EncryptedVar:
                                    decrypted_vars.append(path)
                                else:
                                    new_plain_leaves.append(path)
                        return value
                    vault._transform_leaves(new_vault._data, _find_new_plain_vars, tuple())
                    # Warn about decrypted variables
                    if decrypted_vars:
                        print(f"\n[!] The following vars have been decrypted in this edit:", Color.MEH)
                        print('\n'.join([ f"- { format_key_path(path) }" for path in decrypted_vars ]))
                    # Warn about new plain leaf variables
                    if not new_vault.full_encryption and new_plain_leaves:
                        print(f"\n[!] The following plain vars have been added in this edit:", Color.MEH)
                        print('\n'.join([ f"- { format_key_path(path) }" for path in new_plain_leaves ]))
                    # Log changes
                    if log_enabled:
                        logger.add_log_entry(vault, new_vault, comment=f"{ config.command } command via CLI")
                else:
                    print(f"File unchanged.")
                break

# View command

if config.command == 'view':
    vault_path: str = resolve_vault_path(config.vault_path)
    try:
        vault = VaultFile(vault_path, keyring=keyring)
        if config.as_json:
            print_json(vault.as_json())
        else:
            print_yaml(vault.as_plain())
    except YAMLFormatError:
        if config.as_json:
            raise UnsupportedGenericFileOperation(operation='--json')
        with open(vault_path) as file:
            content: str = file.read()
            print(keyring.decrypt(content) if VaultKey.is_encrypted(content) else content)

# Info command

if config.command == 'info':
    vault_path: str = resolve_vault_path(config.vault_path)
    vault = VaultFile(vault_path, keyring=keyring)
    # Sort leaf values
    encrypted_leaves: list[tuple[Hashable, ...]] = []
    plain_leaves:     list[tuple[Hashable, ...]] = []
    def _sort_leaf(path: tuple[Hashable, ...], value: Any) -> Any:
        if path != ( SENTINEL_KEY, ):
            (encrypted_leaves if type(value) is EncryptedVar else plain_leaves).append(path)
        return value
    vault._transform_leaves(vault._data, _sort_leaf, tuple())
    # Output results
    if config.as_json:
        _data: dict = {
            'full_encryption': vault.full_encryption,
            'encrypted_leaves': encrypted_leaves,
            'plain_leaves': plain_leaves
        }
        print_json(json.dumps(_data, indent=2))
    else:
        print('Encrypted leaf values:', Color.GOOD)
        if encrypted_leaves:
            print('\n'.join([ f"- { format_key_path(key) }" for key in encrypted_leaves ]))
        else:
            print('None', Color.MEH)
        print('\nPlain leaf values:', Color.GOOD)
        if plain_leaves:
            print('\n'.join([ f"- { format_key_path(key) }" for key in plain_leaves ]))
        else:
            print('None', Color.MEH)

# Encrypt & Decrypt & Is-Encrypted commands

if config.command in [ 'encrypt', 'decrypt', 'is-encrypted' ]:
    # File target
    if config.target_type == 'file':
        vault_path: str = resolve_vault_path(config.target)
        is_generic: bool = False
        try:
            vault = VaultFile(vault_path, keyring=keyring)
            is_enc: bool = vault.full_encryption
        except YAMLFormatError as e:
            print('Invalid vault format, will be treated as a generic file', Color.MEH)
            with open(vault_path) as file:
                is_enc = VaultKey.is_encrypted(file.read())
            is_generic = True
        if config.command in [ 'encrypt', 'decrypt' ]:
            if is_enc == (config.command == 'encrypt'):
                print(f"Vault is already { 'en' if is_enc else 'de' }crypted.", Color.GOOD)
            else:
                is_enc = (config.command == 'encrypt')
                # Generic file
                if is_generic:
                    with open(vault_path, 'r+') as file:
                        content: str = file.read()
                        file.seek(0)
                        file.truncate()
                        file.write(keyring.encrypt(content) if is_enc else keyring.decrypt(content))
                # Vault file
                else:
                    vault.full_encryption = is_enc # type: ignore
                    vault.save() # type: ignore
                print(f"Vault { 'en' if is_enc else 'de' }crypted.", Color.GOOD)
        else:
            if config.quiet:
                exit(0 if is_enc else 100)
            else:
                print(f"Vault is { 'fully encrypted' if is_enc else 'plain or hybrid' }.", Color.GOOD if is_enc else Color.MEH)
    # String target
    else:
        is_encrypted: bool = VaultKey.is_encrypted(config.target)
        # The key may not be passed properly, in which case we auto-convert literal '\n' to newlines
        # We can assume an encrypted value should not contain any literal backslashes
        if is_encrypted:
            config.target = config.target.replace('\\n', '\n')
        if config.command in [ 'encrypt', 'decrypt' ]:
            if is_encrypted == (config.command == 'encrypt'):
                if not config.quiet:
                    print(f"Value is already { 'en' if is_encrypted else 'de' }crypted.", Color.GOOD)
                else:
                    print(config.target)
            else:
                if not config.quiet:
                    print(f"{ 'En' if not is_encrypted else 'De' }crypted value:", Color.GOOD)
                print(keyring.encrypt(config.target) if (config.command == 'encrypt') else keyring.decrypt(config.target))
        else:
            if config.quiet:
                exit(0 if is_encrypted else 100)
            else:
                print(f"Value is { 'encrypted' if is_encrypted else 'plain' }.", Color.GOOD if is_encrypted else Color.MEH)

# Rekey command

if config.command == 'rekey':
    vault_path: str = resolve_vault_path(config.vault_path)
    if not config.encryption_key:
        print(f"No explicit encryption key specified, falling back to '{ keyring.encryption_key.id }'", Color.MEH)
    # Since ciphers are usually not changed from load to save, we force re-encryption by loading from an editable
    vault = VaultFile(vault_path, keyring=keyring)
    vault = VaultFile.from_editable(vault, vault.as_editable())
    vault.save()
    print(
        f"Re-encrypted vault with key '{ keyring.encryption_key.id }' and a { 'fixed' if config.fixed_salt else 'random' } salt",
        Color.GOOD
    )

# Convert command

if config.command == 'convert':
    vault_path: str = resolve_vault_path(config.vault_path)
    vault = VaultFile(vault_path, keyring=keyring)
    @logger.log_changes(vault, comment=f"{ config.command } command via CLI", enable=log_enabled)
    def _convert() -> None:
        vault.full_encryption = not vault.full_encryption
        def _encrypt_decrypt(path: tuple[Hashable, ...], value: Any) -> Any:
            if path == ( SENTINEL_KEY, ):
                return value
            if not vault.full_encryption and type(value) is not EncryptedVar:
                return EncryptedVar(keyring.encrypt(value), name=str(path[-1]))
            if vault.full_encryption and type(value) is EncryptedVar:
                return keyring.decrypt(value.cipher)
            return value
        vault._transform_leaves(vault._data, _encrypt_decrypt, tuple())
        vault.save()
        print(f"Vault converted to { 'outer' if vault.full_encryption else 'inner' } encryption.", Color.GOOD)
        if not vault.full_encryption:
            print('Please check the vault to make sure all secrets have been encrypted!', Color.MEH)
    _convert()

# Grep command

if config.command == 'grep':
    # Resolve files and dirs to all file paths
    raw_target_paths: list[str] = [ resolve_vault_path(target, allow_dirs=True) for target in config.targets ]
    target_files: list[str] = []
    for path in raw_target_paths:
        if os.path.isdir(path):
            _targets: list[str] = glob(os.path.join(path, '**' * config.recurse, '*'), recursive=config.recurse, include_hidden=True)
            target_files += [ _path for _path in _targets if os.path.isfile(_path) ]
        else:
            target_files.append(path)
    # Filter out non-YAML and non-YAML-dict files
    targets: list[VaultFile] = []
    for path in target_files:
        try: targets.append(VaultFile(path, keyring=keyring))
        except: debug(f"Skipping non-YAML file { path }")
    # Search targets
    matches: dict = {}
    for vault in targets: # type: ignore
        matches[vault.vault_path] = []
        # Keys/Values only mode
        if getattr(config, 'limit_grep', None):
            _search_fn: Callable = vault.search_keys if config.limit_grep == 'keys' else vault.search_leaf_values
            _results: list[tuple[Hashable, ...]]  = _search_fn(config.query, is_regex=config.is_regex) # type: ignore
            matches[vault.vault_path] += [ { 'key': key, 'value': vault.get(key, decrypt=True) } for key in _results ]
        # Text matching mode
        else:
            _results: list[MatchLocation] = \
                vault.search_vaulttext(config.query, is_regex=config.is_regex, from_plain=config.plain_format, multiline=config.multiline) # type: ignore
            _text: str = vault.as_plain() if config.plain_format else vault.as_editable()
            _lines: list[str] = _text.split('\n')
            for location in _results:
                # Find actual text value (lines and columns are 1-indexed, so we have to subtract 1)
                _first_char: int = sum(map(len, _lines[:(location[0][0] - 1)])) + (location[0][0] - 1) + (location[0][1] - 1)
                _final_char: int = sum(map(len, _lines[:(location[1][0] - 1)])) + (location[1][0] - 1) + (location[1][1] - 1)
                matches[vault.vault_path].append({
                    'value'  : _text[_first_char:_final_char],
                    'context': _lines[(location[0][0] - 1):(location[1][0])],
                    'start'  : location[0],
                    'end'    : location[1]
                })
        # Remove empty results
        if not matches[vault.vault_path]:
            del matches[vault.vault_path]
        if config.quiet and matches:
            exit(0)
    if config.quiet and not matches:
        exit(100)
    # Output JSON
    if config.as_json:
        print_json(json.dumps(matches, indent=2))
    elif not matches:
        print('No matches found.', Color.MEH)
    # Output keys-only/values-only
    elif getattr(config, 'limit_grep', None):
        print(f"Found { 'keys' if config.limit_grep == 'keys' else 'leaf values' } matching query.", Color.GOOD)
        for file_path in matches:
            print(f"In { file_path }:")
            for match in matches[file_path]:
                print('- ', end='')
                print(format_key_path(match['key']), Color.GOOD if config.limit_grep == 'keys' else Color.INFO, end='')
                print(' ==> ', end='')
                print(match['value'], Color.GOOD if config.limit_grep == 'values' else Color.INFO)
    # Output text matches
    else:
        print('Found text matching query.', Color.GOOD)
        for file_path in matches:
            print(f"\nIn { file_path }:")
            for match in matches[file_path]:
                _omission: str = colored('[...]', Color.MEH.value)
                _value: str = f"{ colored(match['value'].split('\n')[0], Color.GOOD.value) }{ _omission if len(match['context']) > 1 else '' }"
                print(f"@L{ match['start'][0] }:{ match['start'][1] } { _value }")
                try:
                    print_yaml('\n'.join(match['context']))
                except:
                    print('\n'.join(match['context']), Color.DEBUG)

# Diff & Changes command

if config.command in [ 'diff', 'changes' ]:
    old_vault_path: str = resolve_vault_path(config.old_vault)
    new_vault_path: str = resolve_vault_path(config.new_vault)
    old_vault = VaultFile(old_vault_path, keyring=keyring)
    new_vault = VaultFile(new_vault_path, keyring=keyring)
    # Diff command
    if config.command == 'diff':
        print_diff(new_vault.diff(old_vault, context_lines=config.context_lines, show_filenames=True))
    # Changes command
    else:
        decrypted_vars, removed_vars, changed_vars, added_vars = new_vault.changes(old_vault)
        json_result: dict = { 'added': added_vars, 'removed': removed_vars, 'changed': changed_vars, 'decrypted': decrypted_vars }
        # JSON
        if config.as_json:
            print_json(json.dumps(json_result, indent=2))
        # Tree view
        else:
            old_tree: Any = dict(old_vault.decrypted_vars)
            new_tree: Any = dict(new_vault.decrypted_vars)
            branches: list[tuple[tuple[Hashable, ...], str | None]] = []
            # Build branches by traversing the data
            # XXX This code makes me sad :(
            def _traverse_data(path: tuple[Hashable, ...], value: Any, _change_inheritance=None) -> None:
                for _added_path in added_vars:
                    if path == _added_path[:-1]:
                        branches.append(( _added_path, 'added' ))
                        _traverse_data(_added_path, new_vault.get(_added_path), _change_inheritance='added')
                if isinstance(value, dict | list | tuple):
                    # Generate type-appropriate indices
                    if isinstance(value, dict):
                        keys: list[Hashable] = sorted(value.keys())
                    else:
                        keys: list[Hashable] = list(range(len(value)))
                    # Depth-first traversal into the data while recording branch types
                    for key in keys:
                        _path = path + ( key, )
                        _change_type: str | None = _change_inheritance
                        for change_type in json_result:
                            if _path in json_result[change_type]:
                                if change_type == 'changed' and _path in json_result['decrypted']:
                                    continue
                                _change_type = change_type
                                break
                        if ( _path, _change_type ) not in branches:
                            branches.append(( _path, _change_type ))
                        _traverse_data(_path, value[key], _change_inheritance=_change_type) # type: ignore
                        if _change_type not in [ 'removed', None ]:
                            _traverse_data(_path, new_vault.get(_path), _change_inheritance='added') # type: ignore
                elif value is not None:
                    if path:
                        _change_type: str | None = _change_inheritance
                        for change_type in json_result:
                            if path in json_result[change_type]:
                                if change_type == 'changed' and path in json_result['decrypted']:
                                    return
                                _change_type = change_type
                                break
                        if ( path, _change_type ) not in branches:
                            branches.append(( path, _change_type ))
            _traverse_data(tuple(), old_tree)
            # Preamble
            print('Branch symbols', Color.TREE_TITLE)
            print('(+) Added node', Color.TREE_ADDED)
            print('(-) Removed node', Color.TREE_REMOVED)
            print('(~) Changed node', Color.TREE_CHANGED)
            print('(!) Decrypted node', Color.TREE_DECRYPTED)
            print('(=) Unchanged node', Color.TREE_UNCHANGED)
            std_print()
            # Branches from depth-first search
            print('Vault changes', Color.TREE_TITLE)
            branches.sort()
            print('│', Color.TREE_UNCHANGED)
            for _index, branch in enumerate(branches):
                # Prepare branch data
                key: tuple[Hashable, ...] = branch[0] # type: ignore
                key_depth: int = len(key) - 1
                change_symbol: str = { 'added': '(+)', 'changed': '(~)', 'removed': '(-)', 'decrypted': '(!)', None: '(=)' }[branch[1]]
                change_color : str = {
                    'added': Color.TREE_ADDED, 'changed': Color.TREE_CHANGED, 'removed': Color.TREE_REMOVED,
                    'decrypted': Color.TREE_DECRYPTED, None: Color.TREE_UNCHANGED
                }[branch[1]]
                # Print with color and symbol
                _next_depth: int = -1 if (_index + 1) == len(branches) else len(branches[_index + 1][0]) - 1
                d0_line: str = (('├' if _index < (len(branches) - 1) else '└' ) + '──') if key_depth == 0 else '│'
                prefix: str = f"{ d0_line }{ '  ' * key_depth }{ '' if key_depth == 0 else ('└─' if _next_depth != key_depth else '├─') } "
                print(prefix, Color.TREE_UNCHANGED, end='')
                print(f"{ change_symbol } { key[-1] }", change_color)

# File-Daemon command

if config.command == 'file-daemon':
    target_path: str = os.path.abspath(config.target_root)
    if os.path.isfile(target_path) or (os.path.isdir(target_path) and os.listdir(target_path)):
        if config.force:
            for child in map(lambda c: os.path.join(target_path, c), os.listdir(target_path)):
                if os.path.isfile(child):
                    os.unlink(child)
                else:
                    rmtree(child, ignore_errors=True)
        else:
            raise FileExistsError(f"Cannot create sync root at { target_path } as the path already exist and is not empty")
    # Resolve sources
    if config.include_default_dirs:
        for dir_path in ( 'host_vars', 'group_vars', 'vars' ):
            if os.path.isdir(dir_path):
                config.sources.append([ os.path.abspath(dir_path), dir_path ])
    sources: set[tuple[str, str]] = {
        ( resolve_vault_path(path, allow_dirs=True), os.path.abspath(os.path.join(target_path, subtarget)) ) for path, subtarget in config.sources 
    }
    # Validity checks
    for path, subtarget in sources:
        if not Path(subtarget).is_relative_to(target_path):
            raise ValueError(f"Target subpath must be a path that is relative or inside the target root path")
        for _path, _target in sources:
            if _target == subtarget and _path != path:
                raise ValueError(f"Sources may not have the same target subpath, found identical target for { _path } and { path }")
    # Create target dir and record if we had to create it for later cleanup
    already_existed: bool = os.path.isdir(target_path)
    os.makedirs(target_path, mode=0o700, exist_ok=True)
    # Cleanup handler
    def _cleanup_daemons(daemons, delete_root) -> None:
        print('\nStopping file daemons and cleaning up files...')
        [ daemon.stop(delete=False) for daemon in daemons ] # type: ignore
        # Only delete the root directory if we created it ourselves
        if delete_root:
            rmtree(target_path, ignore_errors=True)
        else:
            for child in map(lambda c: os.path.join(target_path, c), os.listdir(target_path)):
                if os.path.isfile(child):
                    os.unlink(child)
                else:
                    rmtree(child, ignore_errors=True)
        print('Goodbye.')
    # Create daemons
    def _error_callback(daemon: VaultDaemon, operation: str, err: Exception) -> None:
        print(f"An error occurred in { daemon } during { operation } operation:", Color.BAD)
        print(err, Color.BAD)
    def _debug_out(daemon: VaultDaemon, msg: Any) -> None:
        debug(f"FileDaemon({ daemon.target_file if daemon.target_file else daemon.target_dir }): { msg }")
    daemons: list[VaultDaemon] = [
        VaultDaemon(path, target, keyring, recurse=config.recurse, error_callback=_error_callback, debug_out=_debug_out)
        for path, target in sources
    ]
    atexit.register(_cleanup_daemons, daemons=daemons, delete_root=(not already_existed))
    # Extra interrupt handler to silence error
    signal.signal(signal.SIGINT, lambda *_: exit(0))
    # Start file daemons
    [ daemon.start(stop_on_exit=False) for daemon in daemons ]
    print(f"{ len(daemons) } file daemon(s) running.", Color.GOOD)
    print('Interrupt the program to stop and delete the target directory.')
    # Idle
    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        exit(0)

# Get & Set & Del commands

if config.command in [ 'get', 'set', 'del' ]:
    vault_path: str = resolve_vault_path(config.vault_path)
    vault = VaultFile(vault_path, keyring=keyring)
    key: tuple[Hashable] = resolve_key_path(config.key_segments)
    # Get command
    if config.command == 'get':
        value: Any = vault.get(key, default=Unset, decrypt=config.decrypt_value)
        if type(value) is EncryptedVar:
            value = value.cipher
        if type(value) is ProtoEncryptedVar:
            value = value.plaintext
        # Early abort
        if (config.as_json or config.quiet) and value is Unset:
            exit(100)
        # Output JSON
        if config.as_json:
            # Custom decoder for encrypted vars
            def _decode_vars(obj) -> Any:
                if type(obj) is EncryptedVar:
                    return obj.cipher
                if type(obj) is ProtoEncryptedVar:
                    return obj.plaintext
                raise TypeError(f"{ type(obj) } cannot be serialized into JSON")
            json_code: str = json.dumps(value, default=_decode_vars, indent=2)
            print_json(json_code)
        # Output nothing but the raw YAML
        elif config.quiet:
            yaml_code: str = vault._dump_to_str(value).strip('\n') if isinstance(value, dict | list | tuple) else str(value)
            print_yaml(yaml_code)
        # Output text with extra messages
        else:
            print(f"Key: { format_key_path(key) }")
            if value is Unset:
                print('The key could not be found in the vault.', Color.MEH)
            else:
                yaml_code: str = vault._dump_to_str(value).strip('\n') if isinstance(value, dict | list | tuple) else str(value)
                std_print()
                print_yaml(yaml_code)
    # Set & Del command
    else:
        @logger.log_changes(vault, comment=f"{ config.command } command via CLI", enable=log_enabled)
        def _set_del() -> None:
            old_vault: VaultFile = vault.copy()
            if not getattr(config, 'quiet', False):
                print(f"Key: { format_key_path(key) }")
            # Set command
            if config.command == 'set':
                value: Any = yaml.safe_load(config.value)
                if type(value) is not str and config.encrypt_value:
                    print('Only plain string leaves will be encrypted, not the entire object.', Color.MEH)
                vault.set(key, value, overwrite=True, create_parents=True, encrypt=config.encrypt_value)
                vault.save()
                print('Value has been set.\n', Color.GOOD)
            # Del command
            else:
                result: Any = vault.pop(key, default=Unset)
                if config.quiet:
                    vault.save()
                    exit(100 if result is Unset else 0)
                elif result is Unset:
                    print('The key could not be found in the vault.', Color.MEH)
                    exit(0)
                else:
                    print('The key has been deleted.\n', Color.GOOD)
                    vault.save()
            print_diff(vault.diff(old_vault, show_filenames=True))
        _set_del()

# Entry point for python package
def main() -> None:
    pass
