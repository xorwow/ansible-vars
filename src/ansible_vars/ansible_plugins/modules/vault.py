# Module stub so documentation for the `vault` action plugin can be loaded via `ansible-doc -t module vault`

# Beware: this must be a pure raw string without type hints, as `ansible-doc` performs "dumb" parsing of the raw text in this file
DOCUMENTATION = r'''
---
module: vault
short_description: Get or set a value in an Ansible vault or vars file.
version_added: "2.19.2"
requirements:
  - ansible-vars
author:
  - Atlas (@xorwow)
description:
  - Reads or updates values in an encrypted or plain vault or vars file.
  - When C(value) is provided, the module runs in SET mode and writes to the vault.
  - When C(value) is omitted, the module runs in GET mode and returns the decrypted value.
  - Designed for local vault and vars files, does not work on remote machines.
options:
  # Common options
  file:
    description:
      - Path to the local vault file to read or modify.
      - Interpreted relative to the C(playbook_dir) if not absolute.
    required: true
    type: path
  path:
    description:
      - Path to the value within the vault data structure, as a list of int or str keys.
      - Supports the special key C(+) when in SET mode to add an element to a list.
    required: true
    type: list
    elements: raw
  create_file:
    description:
      - Whether to create the file if it does not exist.
      - When enabled, creates a plain/hybrid file as needed (beware that it won't be fully encrypted!).
    type: bool
    default: false
  passphrase:
    description:
      - Passphrase to use for encryption and to try along all other detected keys for decryption.
      - Defaults to the first auto-detected vault key if not provided.
      - Auto-detection tries to infer keys from your C(ansible.cfg).
      - Also used for the C(log_changes) option.
    deprecated:
      removed_in: 2.19.2
      why: To encourage referencing proper vault IDs, this has been replaced by C(vault_secrets) and C(encryption_key).
      alternative: Use C(vault_secrets) and C(encryption_key) instead.
    required: false
    type: str
  vault_secrets:
    description:
      - Allows you to manually add vault secrets to the list of auto-detected ones.
      - Auto-detection tries to infer keys from your C(ansible.cfg).
      - Expects a dict mapping vault IDs to passphrases. These secrets will be inserted before any auto-detected secrets.
      - The first loaded secret is used for encryption if C(encryption_key) is not set. Also affects the C(log_changes) option.
      - All loaded secrets are tried for decryption.
    required: false
    type: dict
    elements: str
  # GET options
  default:
    description:
      - Default value to return when the vault path does not exist (GET mode only).
      - If omitted, the task fails on an unknown path.
    required: false
  # SET options
  value:
    description:
      - Value to create or update at the specified path (SET mode only).
      - When present, triggers write/update behavior. If omitted, GET mode is used.
    required: false
  encrypt:
    description:
      - Whether to encrypt the value (or its leaf nodes in case of a non-scalar) (SET mode only).
      - Ansible only supports encrypting string values. Objects are traversed and string leaves encrypted. Numbers are left plain.
    type: bool
    default: true
  encryption_key:
    description:
      - Vault ID of the secret that should be used for encryption of the C(value) and the C(log_changes) log (SET mode only).
      - The first loaded secret is used for encryption if C(encryption_key) is not set.
      - Can reference an auto-detected secret or one added manually via the C(vault_secrets) option.
      - See C(vault_secrets) for more details about secret loading.
    required: false
    type: str
  create_path:
    description:
      - Whether to create missing path segments as dictionaries (SET mode only).
      - The leaf segment of the path will always be created and set to C(value) if it does not exist.
    type: bool
    default: false
  log_changes:
    description:
      - Optional path to a log file or directory where changes will be recorded as encrypted YAML (SET mode only).
      - Mixing encryption keys / passphrases within a log is not supported. You can set an explicit one to use via C(encryption_key).
      - When a directory is given, a file will be created based on the used encryption key to ensure key-unique logs.
      - For auto-detected keys, file names will be based on the vault ID associated with them.
      - For an explicit C(passphrase) (deprecated), the file name is based on the first 8 chars of the secret's SHA-1 hash.
      - Plain logging is not supported, an encryption key must be present either from auto-detection or C(vault_secrets).
    required: false
    type: path
seealso:
  - name: Ansible Vault documentation
    description: Details on encrypting and decrypting data using Ansible Vault.
    link: https://docs.ansible.com/ansible/latest/vault_guide/index.html
  - name: C(ansible-vars) documentation and source code
    description: The backend library of this plugin. Contains more detailed documentation about vault interactions.
    link: https://github.com/xorwow/ansible-vars
notes:
  - Beware that running this action in diff mode may leak secrets to your terminal and attached callback plugins.
  - This is only a module stub, used for documentation. Only the associated C(vault) action plugin is executable.
  - Setting values might impact comments and Jinja2 blocks around the affected area of the vault. See C(ansible-vars) documentation.
  - This plugin does not work well for concurrently modifying the same vault. Set C(serial) or C(throttle) to 1 where applicable.
'''

# Beware: this must be a pure raw string without type hints, as `ansible-doc` performs "dumb" parsing of the raw text in this file
EXAMPLES = r'''
- name: Get a passphrase from a vault
  vault:
    file: vars/auth.yml
    path: [ root_pws, 0, my_machine ] # VAULT_DATA['root_pws'][0]['my_machine']
    default: NO_PASS
  register: root_pass
- name: Output passphrase
  debug:
    msg: >-
      The root passphrase for my_machine is {{ 'unset' if root_pass.is_default else root_pass.value }}.
      It is stored {{ 'encrypted' if root_pass.is_encrypted else 'plainly' }}.

- name: Update a value in a vault, creating the vault if necessary
  vault:
    file: "host_vars/{{ inventory_hostname }}/ips.yml"
    create_file: true
    path: ssh # shorthand for single-segment path `[ ssh ]`
    value: 123.99.42.1
    encrypt: false

- name: Store a new passphrase in a vault, and log the changes
  vault:
    file: vars/backups.yml
    path: [ repos, my_machine, pass ]
    value: my_secret_passphrase
    encrypt: true # uses the first auto-detected secret for encryption
    create_path: true # create any non-existent keys as dictionaries along the way
    log_changes: /tmp/backup_changes.yml # logs any changes to this file as encrypted YAML, using the same key as the SET action

- name: Append a complex element to the list data_points using a custom encryption key
  vault:
    file: /tmp/data.yml
    create_file: true
    path: [ data_points, +, raw ] # + is a special symbol: if a list is encountered here, append to it
    create_path: true
    value: { x: [ 'abc', 'def' ] }
    encrypt: true
    vault_secrets: # inserted into the keyring before any auto-detected secrets
        exp_vaults: my_secret_passphrase
        prod_vaults: my_other_secret_passphrase
    encryption_key: prod_vaults # custom key for encryption, can reference a key loaded from ansible.cfg or `vault_secrets`
    log_changes: /tmp # creates a key-unique log file in /tmp with a name based on the `encryption_key` ID
'''

# Beware: this must be a pure raw string without type hints, as `ansible-doc` performs "dumb" parsing of the raw text in this file
RETURN = r'''
value:
  description: The decrypted value at the specified path (will mirror C(value) argument in SET mode).
  type: raw
  returned: always
is_default:
  description: Indicates whether the returned value was the provided default (will always be false in SET mode).
  type: bool
  returned: always
is_encrypted:
  description: Whether the stored value was encrypted (will mirror C(encrypt) argument in SET mode).
  type: bool
  returned: always
'''
