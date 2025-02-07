# Custom exceptions for ansible-vars

# YAML parsing

class UnsupportedGenericFileOperation(Exception):
    '''The requested operation or flag is not available for generic (i.e. non-YAML-dictionary) files.'''

    def __init__(self, *args: object, operation: str | None = None) -> None:
        super().__init__(
            f"The requested operation or flag is not available for generic files{ f': { operation }' * bool(operation) }", *args
        )

class YAMLFormatError(Exception):
    '''The supplied content is not a valid Ansible YAML file. Supports passing the triggering parent exception.'''
    
    def __init__(self, *args: object, parent: Exception | None = None) -> None:
        self.parent: Exception | None = parent
        super().__init__(*args)

# VaultKey management

class KeyExistsError(KeyError):
    '''The key you wish to create already exists, but overwriting it is disallowed.'''
    pass

class NoVaultKeysError(Exception):
    '''No vault keys are available for en-/decryption.'''
    pass

class NoMatchingVaultKeyError(Exception):
    '''No vault key matched the ciphertext or no vault key matched the queried ID.'''
    pass

class VaultKeyMatchError(Exception):
    '''Vault key did not match the ciphertext.'''
    pass
