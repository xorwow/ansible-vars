import os.path
from typing import Any
from hashlib import sha1
from traceback import format_exc
from importlib.util import spec_from_file_location, module_from_spec

from ansible.utils.display import Display
from ansible.constants import config
from ansible.plugins.action import ActionBase
from ansible.module_utils._internal._datatag import AnsibleTagHelper
from ansible_vars.vault_crypt import VaultKey, VaultKeyring
from ansible_vars.vault import VaultFile, EncryptedVar
from ansible_vars.util import DiffFileLogger
from ansible_vars.constants import ThrowError

from ..modules import vault as module_stub

# For documentation, see the associated module stub (or run `ansible-doc -t module vault` if you loaded the stub)

class ActionError(Exception):
    '''An error that should be returned via the task's `msg` parameter with a `failed` state.'''
    
    def __init__(self, msg: str) -> None:
        self.msg: str = msg
        super().__init__(msg)

# Sentinel for an unset value
OMITTED: object = object()

# Path of `ansible.cfg` if loaded
CONFIG_PATH: str | None = config._config_file

class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None) -> dict[str, Any]:
        '''Run the `vault` action. See documentation for valid arguments and expected behavior.'''
        try:
            super(ActionModule, self).run(tmp, task_vars)

            args: dict[str, Any] = self._task.args.copy() # all args are recursively tagged (i.e. class-wrapped) by Ansible :(
            args = ActionModule.recursive_untag(args)
            set_mode: bool = 'value' in args

            # Validate common args
            if 'file' not in args or not isinstance(args['file'], str):
                raise ActionError('Requires `file` argument to be a path.')
            if 'path' not in args or not isinstance(args['path'], list | str | int):
                raise ActionError('Requires `path` argument to be a list of segments or a single str/int segment.')
            if 'create_file' in args and not isinstance(args['create_file'], bool):
                raise ActionError('Requires `create_file` argument to be a bool.')
            if not args.get('create_file', False) and not os.path.isfile(args['file']):
                raise ActionError('Requires `file` argument to be an actual file unless `create_file` is set.')
            if 'passphrase' in args and not isinstance(args['passphrase'], str):
                raise ActionError('Requires `passphrase` argument to be a str secret.')
            if 'passphrase' in args:
                self._display.warning('The `passphrase` argument has been deprecated in favor of `vault_secrets` and `encryption_key`.')
            if 'vault_secrets' in args and not isinstance(args['vault_secrets'], dict):
                raise ActionError('Requires `vault_secrets` argument to be a dict mapping vault IDs to passphrases.')
            if 'passphrase' in args and 'vault_secrets' in args:
                raise ActionError('`passphrase` and `vault_secrets` are mutually exclusive.')

            # Validate GET args
            if set_mode and 'default' in args:
                self._display.warning('Ignoring `default` argument as we\'re setting a value.')

            # Validate SET args
            for _arg in ( 'value', 'encrypt', 'encryption_key', 'create_path', 'log_changes' ):
                if not set_mode and _arg in args:
                    self._display.warning(f"Ignoring `{ _arg }` argument as we\'re not setting a value.")
            if 'encrypt' in args and not isinstance(args['encrypt'], bool):
                raise ActionError('Requires `encrypt` argument to be a bool.')
            if 'create_path' in args and not isinstance(args['create_path'], bool):
                raise ActionError('Requires `create_path` argument to be a bool.')
            if 'log_changes' in args and not isinstance(args['log_changes'], str):
                raise ActionError('Requires `log_changes` argument to be a dir or file path.')
            if 'encryption_key' in args and not isinstance(args['encryption_key'], str):
                raise ActionError('Requires `encryption_key` argument to be a vault ID str.')
            if 'passphrase' in args and 'encryption_key' in args:
                raise ActionError('`passphrase` and `encryption_key` are mutually exclusive.')

            # Collect common args
            file: str = args['file']
            if not os.path.isabs(file) and (base_dir := (task_vars or {}).get('playbook_dir', None)):
                file = os.path.join(base_dir, file)
            path: tuple[str | int] = tuple(args['path'] if isinstance(args['path'], list) else [ args['path'] ])
            create_file: bool = args.get('create_file', False)
            passphrase: str | None = args.get('passphrase', None)
            vault_secrets: dict[str, str] = args.get('vault_secrets', {})

            # Collect GET args
            default: Any = args.get('default', OMITTED)

            # Collect SET args
            value: Any = args.get('value', OMITTED)
            encrypt: bool = args.get('encrypt', True)
            encryption_key: str | None = args.get('encryption_key', args.get('passphrase', None))
            create_path: bool = args.get('create_path', True)
            log_changes: str | None = args.get('log_changes', None)

            # Prepare return values
            ret_value: Any = value
            is_encrypted: bool = False
            is_default: bool = False
            is_changed: bool = False
            diff: list[dict[str, str]] = []

            # Load secrets
            config_dir: str = os.path.dirname(CONFIG_PATH) if CONFIG_PATH else (task_vars or {}).get('playbook_dir', None)
            secrets: list[VaultKey] = [ VaultKey(_pass, _id) for _id, _pass in vault_secrets.items() ]
            if passphrase: # `passphrase` has been deprecated
                secrets = [ VaultKey(passphrase, sha1(passphrase.encode()).hexdigest()[:8]) ]
            keyring: VaultKeyring = VaultKeyring(keys=secrets, detection_source=config_dir)
            if encryption_key:
                keyring.default_encryption_key = keyring.key_by_id(encryption_key)

            # Load vault
            if not os.path.isfile(file) and create_file:
                orig_vault: VaultFile = VaultFile.create(file, full_encryption=False, keyring=keyring)
            else:
                orig_vault: VaultFile = VaultFile(file, keyring)

            # Perform SET
            if set_mode:
                # Update value
                prev_value: Any = orig_vault.get(path, default=OMITTED, decrypt=True)
                was_encrypted: bool = type(orig_vault.get(path, default=OMITTED, decrypt=False)) is EncryptedVar
                curr_vault: VaultFile = orig_vault.copy()
                curr_vault.set(path, value, overwrite=True, create_parents=(create_path or ThrowError), encrypt=encrypt)
                if not self._task.check_mode:
                    curr_vault.save()
                # Log changes (requires encryption key)
                if log_changes:
                    logger: DiffFileLogger = DiffFileLogger(log_changes, keyring, plain=False)
                    logger.add_log_entry(orig_vault, curr_vault)
                # Update return values
                ret_value = value
                is_encrypted = encrypt
                is_changed: bool = (prev_value != value) or (was_encrypted != is_encrypted)
                diff = [ {
                    'before': orig_vault.as_plain(),
                    'after':  curr_vault.as_plain(),
                    'before_header': orig_vault.vault_path,
                    'after_header':  curr_vault.vault_path
                } ]

            # Perform GET
            else:
                ret_value = orig_vault.get(path, default=OMITTED, decrypt=True)
                is_encrypted = type(orig_vault.get(path, default=OMITTED, decrypt=False)) is EncryptedVar
                if ret_value is OMITTED:
                    if default is OMITTED:
                        raise ActionError(f"Value at path { path } could not be found.")
                    is_default = True
                    ret_value = default

            # Return task results
            return {
                # Ansible fields
                'failed': False,
                'changed': is_changed,
                'diff': diff if self._task.diff else [],
                # Custom fields
                'value': ret_value,
                'is_default': is_default,
                'is_encrypted': is_encrypted
            }

        except ActionError as e:
            return { 'failed': True, 'msg': f"Task error: { e.msg }" }

        except Exception as e:
            self._display.v(f"{ type(e).__name__ } traceback: { format_exc() }") # only with -v
            return { 'failed': True, 'msg': f"{ type(e).__name__ }: { e } (run with -v for trace)" }

    @staticmethod
    def recursive_untag(data: Any) -> Any:
        '''Recursively untags Ansible-tagged values.'''
        data = AnsibleTagHelper.untag(data)
        if isinstance(data, dict):
            data = {
                AnsibleTagHelper.untag(key): ActionModule.recursive_untag(value)
                for key, value in data.items()
            }
        if isinstance(data, list):
            for index, value in enumerate(data):
                data[index] = ActionModule.recursive_untag(value)
        return data

def check_docs_outdated(module_path: str) -> None:
    '''Prints a warning if the given documentation module stub contains outdated documentation.'''
    try:
        # Load module
        if not os.path.isfile(module_path):
            raise FileNotFoundError(f"Module stub '{ module_path }' could not be resolved")
        if (spec := spec_from_file_location('vault', module_path)) is None or spec.loader is None:
            raise ImportError(f"Cannot load vault module from '{ module_path }'")
        spec.loader.exec_module((module := module_from_spec(spec)))
        # Check for outdated documentation
        for doc in ( 'DOCUMENTATION', 'EXAMPLES', 'RETURN' ):
            if not (content := getattr(module, doc, None)):
                raise KeyError(f"{ doc } value not present in '{ module_path }'")
            if content != getattr(module_stub, doc):
                raise ValueError(f"{ doc } value is out of date for '{ module_path }'")
    except Exception as e:
         Display().warning(f"Documentation check for vault plugin: { e } -- please update module file/link")
