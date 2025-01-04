# Vault secret loading and management for ansible-vars

# Standard library imports
import re
from typing import Type

# External library imports
import ansible.constants as Ansible
from ansible.parsing.vault import VaultLib, VaultSecret, AnsibleVaultError
from ansible.cli import DataLoader, CLI

# Internal module imports
from .errors import NoMatchingVaultKeyError, NoVaultKeysError, VaultKeyMatchError

class VaultKey():
    '''
    Represents a single Ansible vault secret and allows to en- and decrypt vault data with it.
    Can be initialized directly from an Ansible secrets tuple `(vault_id | None, VaultSecret)` through `VaultKey.from_ansible_secret`.
    '''

    def __init__(self, secret: str | VaultSecret, vault_id: str | None = None) -> None:
        '''
        Create a new VaultKey from an Ansible VaultSecret or directly from a passphrase.
        Takes an optional vault ID which should be identical to the vault ID used to encrypt any data you wish to decrypt.
        If no ID is supplied, Ansible's default vault identity value is used, which should match all vault IDs.
        Note that IDs are not necessarily unique. For example, the default identity may be used for multiple `VaultKey`s.
        '''
        # Use default vault ID if none is supplied
        self.id: str = Ansible.DEFAULT_VAULT_IDENTITY if vault_id is None else vault_id  # type: ignore
        # Convert passphrase to VaultSecret if necessary
        self.secret: VaultSecret = VaultSecret(secret.encode('utf-8')) if type(secret) is str else secret # type: ignore
        # Pass secret to VaultLib (we need an individual instance because `VaultLib.decrypt` doesn't take an explicit secret)
        self._vaultlib: VaultLib = VaultLib([ self.to_ansible_secret() ])

    @classmethod
    def from_ansible_secret(VaultKey: Type['VaultKey'], secret: tuple[str | None, VaultSecret]) -> 'VaultKey':
        '''Converts an Ansible secrets tuple `(vault_id | None, VaultSecret)` to a `VaultKey` instance.'''
        return VaultKey(secret[1], vault_id=secret[0])

    def to_ansible_secret(self) -> tuple[str, VaultSecret]:
        '''Converts this `VaultKey` into an Ansible secrets tuple `(vault_id | None, VaultSecret)`.'''
        return ( self.id, self.secret )

    @property
    def passphrase(self) -> str | None:
        '''Returns the passphrase associated with the key's secret, or None if it cannot be decoded.'''
        return self.secret.bytes.decode('utf-8') if type(self.secret.bytes) is bytes else None

    @staticmethod
    def is_encrypted(test_me: str) -> bool:
        '''
        Tests if a string is an encrypted Ansible vault string.
        Expects a string with optional YAML tag preamble (`!vault | $ANSIBLE_VAULT;<options>\\n<cipher>`).
        '''
        return VaultLib.is_encrypted(VaultKey._strip_vault_tag(test_me))

    def encrypt(self, plain: str) -> str:
        '''Encrypts a string using this `VaultKey`'s secret.'''
        # Pass our secret directly to the encrypt call to skip expensive secret matching
        # Beware: the encrypt function takes a `secret`, but means just the VaultSecret and not a tuple of (vault_id, VaultSecret)
        # In other calls, `secret` or `secrets` may refer to the tuple(s)
        return self._vaultlib.encrypt(plain, secret=self.secret, vault_id=self.id).decode('utf-8').strip()

    def decrypt(self, vault_cipher: str) -> str:
        '''
        Tries to decrypt a string using this `VaultKey`'s secret.
        Expects a cipher with optional YAML tag preamble (`!vault | $ANSIBLE_VAULT;<options>\\n<cipher>`).
        If the secret does not match the cipher, a `VaultKeyMatchError` will be raised.
        '''
        vault_cipher = VaultKey._strip_vault_tag(vault_cipher)
        try:
            decrypted: bytes = self._vaultlib.decrypt(vault_cipher)
            return decrypted.decode('utf-8').strip()
        except AnsibleVaultError as e:
            if e.message.startswith('Decryption failed (no vault secrets were found that could decrypt)'):
                raise VaultKeyMatchError(f"Could not match cipher with { self }")
            raise e

    @staticmethod
    def _strip_vault_tag(vault_cipher: str) -> str:
        '''Strips extra whitespace and any YAML vault tag preamble from the cipher.'''
        EXTRACTION_PATTERN: str = r'^(?:\s*!vault\s*[\|>]?\-?\s*)?(.*)$'
        match_result: re.Match[str] | None = re.search(EXTRACTION_PATTERN, vault_cipher.strip(), re.DOTALL)
        return vault_cipher.strip() if match_result is None else match_result.group(1).strip()

    def __repr__(self) -> str:
        return f"VaultKey({ self.id })"

class VaultKeyring():
    '''
    A collection of Ansible vault secrets to be used for en- and decrypting vault data.
    Tries to infer available secrets from the caller's present working directory, if it is an Ansible home.
    '''

    def __init__(
            self,
            keys: list[VaultKey] | None = None,
            default_encryption_key: VaultKey | None = None,
            detect_available_keys: bool = True
        ) -> None:
        '''
        Create a new keyring of `VaultKey`s and optionally populate it with the given `keys`.
        Tries to infer available Ansible vault secrets from the caller's present working directory, if it is an Ansible home.
        This is done using the Ansible CLI module. You can disable key inferral by setting `detect_available_keys` to False.
        When decrypting vault data, inferred keys are tried after the explicitly supplied ones.
        Note that the inferral process may cause TTY prompts or other unwanted in- and output.
        
        When encrypting data, you can specify an explicit `VaultKey` to use. If none is specified, `default_encryption_key` is used.
        If no explicit or default keys are available, the first key of the `keys` parameter is used.
        '''
        self.keys: list[VaultKey] = keys or []
        self.default_encryption_key: VaultKey | None = default_encryption_key
        if detect_available_keys:
            self.keys.extend(VaultKeyring.load_cli_secrets())
    
    @property
    def encryption_key(self) -> VaultKey:
        '''
        Get the key used for encryption or raise a `NoVaultKeysError` if none are available.
        If no `default_encryption_key` is set for this instance, the first key of the `keys` array is used.
        Note that you can override this behavior by passing an explicit key to the `encrypt` method.
        '''
        if not (self.default_encryption_key or self.keys):
            raise NoVaultKeysError('No vault keys available for encryption')
        return self.default_encryption_key or self.keys[0]

    def encrypt(self, plain: str, key: VaultKey | None = None) -> str:
        '''
        Encrypts the given vault data using the supplied `VaultKey`.
        If no key is supplied, the `VaultKeyring`'s `default_encryption_key` is used.
        If that key is also unset, the first key of the `VaultKeyring`'s `keys` is used.
        '''
        # If no key is provided, use the default encryption key or first key in `keys`
        if not key:
            key = self.encryption_key
        return key.encrypt(plain)

    def decrypt(self, vault_cipher: str, key: VaultKey | None = None) -> str:
        '''
        Tries to decrypt the given vault data using the supplied `VaultKey`.
        If no key is supplied, all of the `VaultKeyring`'s `keys` are tried in order (by default, inferred keys are last).
        If no key matches the cipher, a `NoMatchingVaultKeyError` will be raised.

        Expects a cipher with optional YAML tag preamble (`!vault | $ANSIBLE_VAULT;<options>\\n<cipher>`).
        '''
        if not key and not self.keys:
            raise NoVaultKeysError('No vault keys available for decryption')
        if key:
            return key.decrypt(vault_cipher)
        # Search for matching key
        for key in self.keys:
            try: return key.decrypt(vault_cipher)
            except VaultKeyMatchError: pass
        # No keys matched
        raise NoMatchingVaultKeyError(f"Found no matching vault key to decrypt cipher in { self }")

    def key_by_id(self, id: str) -> VaultKey:
        '''
        Gets a loaded key by its ID or raises `NoMatchingVaultKeyError` if no key matches the ID.
        If multiple keys share the ID, the first in `keys` is returned.
        '''
        for key in self.keys:
            if key.id == id:
                return key
        raise NoMatchingVaultKeyError(f"No matching key found for ID '{ id }' in { self }")

    @staticmethod
    def load_cli_secrets() -> list[VaultKey]:
        '''
        Tries to infer available Ansible vault secrets from the caller's present working directory, if it is an Ansible home.
        Inferred secrets are converted into `VaultKey`s and returned.
        Note that the inferral process may cause TTY prompts or other unwanted in- and output.
        '''
        # Ansible.DEFAULT_VAULT_IDENTITY_LIST is a list populated with vault IDs inferred from the PWD
        # (i.e. has to be run in ANSIBLE_HOME, else the value is [])
        secrets: list[tuple[str | None, VaultSecret]] = \
            CLI.setup_vault_secrets(DataLoader(), Ansible.DEFAULT_VAULT_IDENTITY_LIST, auto_prompt=False) # type: ignore
        return list(map(VaultKey.from_ansible_secret, secrets))

    def __repr__(self) -> str:
        return f"VaultKeyring({ ', '.join(map(lambda key: key.id, self.keys)) or 'no keys' })"
