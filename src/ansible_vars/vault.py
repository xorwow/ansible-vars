# Vault(file) parsing and management for ansible-vars

# Standard library imports
import os, re, json
from io import StringIO
from functools import reduce
from typing import Type, Hashable, Callable, Any, cast
from difflib import unified_diff

# External library imports
from ruamel.yaml import YAML
from ruamel.yaml.nodes import ScalarNode
from ruamel.yaml.representer import Representer
from ruamel.yaml.constructor import Constructor
from ruamel.yaml.comments import CommentedMap

# Internal module imports
from .constants import ThrowError, octal, Indexable, ChangeList, MatchLocation, SENTINEL_KEY, EDIT_MODE_HEADER, ENCRYPTED_VAR_TAG
from .vault_crypt import VaultKey, VaultKeyring
from .errors import KeyExistsError, NoVaultKeysError, YAMLFormatError

class EncryptedVar():
    '''
    Represents a single encrypted vault variable, initialized with the encrypted content.
    The content should be a str, as Ansible does not directly support other data types in encrypted variables.
    As this class has no `VaultKeyring` access, decryption must be performed externally.
    Note that comparing `EncryptedVar` objects by their `cipher`s usually does not work, as Ansible ciphers contain a random salt.
    This class should be treated as static. Do not change its values, replace it instead.
    '''

    def __init__(self, cipher: str, name: str | None = None) -> None:
        '''Initialize an encrypted variable with an optional variable name. The name is only used for internal representation.'''
        # Encrypted has to hold a string like '$ANSIBLE_VAULT;1.2;AES256;someid\n123456<...>' (the newline is important)
        self.cipher: str = cipher
        self.name: str | None = name

    def __repr__(self) -> str:
        return f"EncryptedVar({ self.name or 'unnamed' })"

    # ruamel.yaml dumper/loader converters

    yaml_tag: str = u'!vault'

    @classmethod
    def to_yaml(EncryptedVar: Type['EncryptedVar'], representer: Representer, var: 'EncryptedVar') -> Any:
        #return representer.represent_str(var.cipher)
        return representer.represent_scalar(u'!vault', var.cipher, style='|')

    @classmethod
    def from_yaml(EncryptedVar: Type['EncryptedVar'], constructor: Constructor, node: ScalarNode) -> 'EncryptedVar':
        cipher: Any = constructor.construct_scalar(node)
        if not isinstance(cipher, str):
            raise TypeError(f"Expected encrypted value to be a str, but got { type(cipher) }")
        return EncryptedVar(cipher, name=node.id)

class ProtoEncryptedVar():
    '''
    A variable marked to be encrypted in a `Vault` editable.
    This class should be treated as static. Do not change its values, replace it instead.
    '''

    def __init__(self, plaintext: str, name: str) -> None:
        '''Initialize a plaintext value marked for encryption with a name for internal representation.'''
        self.plaintext: str = plaintext
        self.name: str = name

    def __eq__(self, __o: object) -> bool:
        if type(__o) is not ProtoEncryptedVar:
            return False
        return self.plaintext == __o.plaintext

    def __repr__(self) -> str:
        return f"ProtoEncryptedVar({ self.name })"

    # ruamel.yaml dumper/loader converters

    yaml_tag: str = ENCRYPTED_VAR_TAG

    @classmethod
    def to_yaml(ProtoEncryptedVar: Type['ProtoEncryptedVar'], representer: Representer, var: 'ProtoEncryptedVar') -> Any:
        return representer.represent_scalar(ENCRYPTED_VAR_TAG, var.plaintext, style=('|' if '\n' in var.plaintext else ''))

    @classmethod
    def from_yaml(ProtoEncryptedVar: Type['ProtoEncryptedVar'], constructor: Constructor, node: ScalarNode) -> 'ProtoEncryptedVar':
        plaintext: Any = constructor.construct_scalar(node)
        if not isinstance(plaintext, str):
            raise TypeError(f"Expected decrypted value to be a str, but got { type(plaintext) }")
        return ProtoEncryptedVar(plaintext.rstrip('\n'), name=node.id)

class Vault():
    '''
    Represents an Ansible vault's contents, with plain and encrypted variables and potentially full vault encryption on top.
    Since full vault encryption is detected from the specified yaml content, do not externally decrypt the vault contents first
    unless you wish to lose full file encryption, or set `Vault.full_encryption` manually after initialization.
    To create a fresh `Vault`, you may also use `Vault.create` and set your desired encryption settings directly.
    To load from and save to a vault file directly, use the `VaultFile` wrapper of this module.

    Note that variable values containing Jinja2 code (e.g. `my_var: "{{ other_var }}"`) are stored in an escaped form by ruamel.yaml.jinja2.
    You should either ignore these values or take care to understand the escape syntax of the plugin before editing them or adding any.
    They can be freely overwritten with non-Jinja2 values and will lose their special status.
    '''

    # Initialization/Loading

    def __init__(self, yaml_content: str, keyring: VaultKeyring | None = None) -> None:
        '''
        Parses a vault's (potentially encrypted) contents. Automatically detects if the content is wholly encrypted.
        If no keyring is supplied, only plain vars and content are supported.
        '''
        # If no keyring is supplied, create an empty one which will raise an error if we try to en-/decrypt anything
        self.keyring: VaultKeyring = keyring or VaultKeyring(keys=None, detect_available_keys=False)
        # Full vault encryption, may also contain single encrypted variables either way
        self.full_encryption: bool
        # Internal variable tree
        # Contains a sentinel key (constants.SENTINEL_KEY)
        self._data: CommentedMap
        # YAML parser, contains YAML metadata needed for exporting the data
        self._parser: YAML
        # Parse the given Jinja2 yaml data and set the relevant variables
        self._parser, self._data, self.full_encryption = self._parse(yaml_content, self.keyring)

    @classmethod
    def create(Vault: Type['Vault'], content: str = '', full_encryption: bool = True, keyring: VaultKeyring | None = None) -> 'Vault':
        '''
        Creates a new vault with desired encryption settings.
        If `content` is set, the vault will be loaded with this Jinja2 yaml text instead of an empty string.
        If `full_encryption` is set to True, the vault will be wholly encrypted in addition to any encrypted variables.
        If no keyring is supplied, only plain vars are supported and enabling `full_encryption` will not work.
        '''
        vault = Vault(content, keyring=keyring)
        vault.full_encryption = full_encryption
        return vault

    @classmethod
    def from_editable(Vault: Type['Vault'], prev_vault: 'Vault', edited_content: str) -> 'Vault':
        '''Converts a YAML vault edited from a `Vault.as_editable` template into a new `Vault`.'''
        # Remove static header (try removing without trailing newline too just in case)
        edited_content = edited_content.replace(EDIT_MODE_HEADER, '', 1)
        edited_content = edited_content.replace(EDIT_MODE_HEADER.strip('\n'), '', 1)
        # Init new vault with edited YAML
        # ProtoEncryptedVar conversion is done in vault parser, so no need to do it here
        vault = Vault(edited_content, keyring=prev_vault.keyring)
        # Copy relevant settings from old vault
        vault.full_encryption = prev_vault.full_encryption
        return vault

    @staticmethod
    def _parse(yaml_content: str, keyring: VaultKeyring) -> tuple[YAML, CommentedMap, bool]:
        '''
        Parses the given Jinja2 yaml string into a CommentedMap.
        Returns the YAML parser holding metadata, the loaded mapping and a flag signifying the string was fully encrypted.
        '''
        # Create a special Jinja2 YAML round-trip parser holding the metadata for Jinja2 blocks, comments and (most) formatting
        parser = YAML(typ='jinja2')
        parser.allow_unicode = True
        parser.preserve_quotes = True
        parser.allow_duplicate_keys = True
        # mapping = dict offset, sequence = list offset within item, offset = list offset before dash
        parser.indent(sequence=2, mapping=2, offset=0)
        # Automatic loading and dumping of EncryptedVars
        parser.register_class(EncryptedVar)
        # Automcatic loading and dumping of encryption marks
        parser.register_class(ProtoEncryptedVar)
        # Decrypt file if wholly encrypted
        if (full_encryption := VaultKey.is_encrypted(yaml_content)):
            yaml_content = keyring.decrypt(yaml_content)
        # Insert a dummy key because our parser can't save the comments of a file without any keys
        yaml_content = Vault._insert_sentinel(yaml_content)
        # Load YAML as CommentedMap
        try:
            data: CommentedMap = parser.load(yaml_content)
        except Exception as e:
            raise YAMLFormatError('Provided content is not valid Ansible YAML code', parent=e)
        # Convert ProtoEncryptedVars to EncryptedVars
        # This is done in parsing instead of in `Vault.from_editable` in case the user creates a vault with protovars
        def _convert_from_proto(_: tuple[Hashable, ...], value: Any) -> Any:
            '''Encrypts leaves marked for encryption.'''
            if type(value) is not ProtoEncryptedVar:
                return value
            return EncryptedVar(keyring.encrypt(value.plaintext), name=value.name)
        Vault._transform_leaves(data, _convert_from_proto, tuple())
        return parser, data, full_encryption

    @staticmethod
    def _insert_sentinel(yaml_content: str) -> str:
        '''Inserts a special key into the given raw YAML string, so the resulting data cannot be empty. Returns the modified YAML.'''
        lines: list[str] = yaml_content.split('\n')
        # Insert our sentinel key right before the explicit end line (`...`)
        for index, line in reversed(list(enumerate(lines))): # look for last occurance
            if line.strip() == '...':
                lines.insert(index, f"{ SENTINEL_KEY }:")
                break
        # If there is no explicit end, just append it to the text
        else:
            lines.append(f"{ SENTINEL_KEY }:")
        return '\n'.join(lines)

    # Dictionary operations

    # A single dict key or a chain of nested dict keys
    DictPath = Hashable | tuple[Hashable, ...]

    @property
    def decrypted_vars(self) -> dict:
        '''A copy of the vault's variables, with any EncryptedVars already decrypted.'''
        return self._decrypted_copy(remove_sentinel=True) # might not have correct YAML metadata, but the values are okay

    def has(self, path: DictPath) -> bool:
        '''Checks if the given key path is present in the vault's data.'''
        try: self._traverse(path, decrypt=False)
        except KeyError: return False
        return True

    def get(
            self, path: DictPath, default: Any | Type[ThrowError] = ThrowError,
            decrypt: bool = False, with_index: bool = False, copy: bool = False
        ) -> Any | tuple[int, Any]:
        '''
        Retrieves a value from the vault's variables by its key path, optionally decrypting it recursively.
        When `default` is set to `ThrowError`, a `KeyError` will be raised if the path does not exist.
        Else, the default value is returned if the path does not exist.
        When `with_index` is set to True, a tuple `(index_in_parent, value)` is returned (index is -1 if defaulted).
        When `copy` or `decrypt` is set to True, a deep copy of the value will be returned.
        '''
        path = Vault._to_path(path)
        try:
            value: Any = self._traverse(path, decrypt=decrypt, copy=copy)
            if with_index:
                parent: Indexable = self._data if not path else self._traverse(path[:-1], decrypt=False)
                if isinstance(parent, dict):
                    key_index: int = next(index for index, key in enumerate(parent) if key == path[-1])
                else:
                    key_index = cast(int, path[-1])
                return (key_index, value)
            return value
        except:
            if default is ThrowError:
                raise KeyError(f"Key path { '.'.join(map(str, path)) } could not be found in { self }")
            return (-1, default) if with_index else default

    def set(
            self, path: DictPath, value: Any, overwrite: bool | Type[ThrowError] = True, # type: ignore
            create_parents: bool | Type[ThrowError] = True, encrypt: bool = False
        ) -> bool:
        '''
        Creates or updates a value in the vault's variables. The value has to be serializable into YAML.
        If the last/only key of the key path does not exist yet, it will be created.
        If the variable is set successfully, `True` is returned. If any of the below checks fail, `False` is returned.
        Be aware that appending a new entry to a list requires the key to be equal to the length of the list (i.e. largest index + 1).
        On updated leaf values, comment and Jinja2 metadata is preserved.
        When appending a new value or editing an indexable item, metadata may get messed up.

        Options:
        - `overwrite`: Controls what happens if a value is already present at the key path
          - `True`: Replace the existing value
          - `False`: Abort silently, returning False
          - `ThrowError`: Raise a KeyError if the key path already exists
        - `create_parents`: Controls if the entire key path should be created if it doesn't exist yet
          - `True`: Create any nested dictionaries needed to traverse to the last key
          - `False`: Abort silently if any but the last key in the path do not exist, returning False
          - `ThrowError`: Raise a KeyError if any but the last key in the path do not exist
        - `encrypt`: Controls if the value should be recursively encrypted before storing it (only plain `str`s get encrypted)
          - `True`: Attempt to copy and convert the value('s leaf values) into an `EncryptedVar` before storing it
          - `False`: Store the value as-is
        '''
        path: tuple[Hashable, ...] = Vault._to_path(path) # XXX typer complains if not explicitly re-typed
        # Encrypt value if necessary
        if encrypt:
            value = Vault._copy_data(value)
            def _encrypt_leaf(_: tuple[Hashable, ...], _value: Any) -> Any:
                '''Transforms strings into `EncryptedVar`s.'''
                if type(_value) is not str:
                    return _value
                name: str | None = str(path[-1]) if path else None
                if VaultKey.is_encrypted(_value):
                    return EncryptedVar(_value, name=name)
                return EncryptedVar(self.keyring.encrypt(_value), name=name)
            if isinstance(value, dict | list):
                Vault._transform_leaves(value, _encrypt_leaf, tuple())
            else:
                value = _encrypt_leaf(tuple(), value)
        # Resolve chain and create parents if necessary, then set value for last item
        parent: Any = self._data
        par_path: str = ''
        for _index, segment in enumerate(path):
            is_last: bool = (_index + 1) == len(path)
            # Check if parent is indexable
            if not isinstance(parent, dict | list):
                raise TypeError(f"Indexing into a { type(parent) } is not supported ({ par_path })")
            # Check if index is of correct type
            if isinstance(parent, list) and type(segment) is not int:
                raise TypeError(f"Type of list index has to be int, got { type(segment) } ({ par_path }[{ segment }])")
            # Check if the current segment has to be created in the parent
            if (isinstance(parent, dict) and segment not in parent) or (isinstance(parent, list) and cast(int, segment) >= len(parent)):
                if not is_last:
                    if create_parents is ThrowError:
                        raise KeyError(f"Parents of { '.'.join(map(str, path)) } could not be resolved ({ segment } not in { par_path })")
                    if not create_parents:
                        return False
                # Create nested dictionary as next parent or set value of leaf, depending on index
                segment_value: Any = value if is_last else CommentedMap()
                # Check that a new list item has a specified index of (largest list index + 1)
                # This is done because the method of creating an index of e.g. 7 in a list of length 3 is ambiguous
                if isinstance(parent, list) and segment != len(parent):
                    raise IndexError(f"Creating new list item, but index { segment } exceeds appendment index { len(parent) } ({ par_path })")
                # Set value
                if isinstance(parent, dict):
                    parent[segment] = segment_value # type: ignore
                else:
                    parent.append(segment_value)
            # Else, replace the existing value if we are at the end of the path
            elif is_last:
                if overwrite is ThrowError:
                    raise KeyExistsError(f"Key { segment } already exists in { par_path }")
                if not overwrite:
                    return False
                parent[segment] = value # type: ignore
            # Advance parent
            parent = parent[segment] # type: ignore
            par_path = f"{ par_path }.{ segment }"
        return True

    def pop(
            self, path: DictPath, default: Any | Type[ThrowError] = ThrowError,
            decrypt: bool = False, with_index: bool = False
        ) -> Any | tuple[int, Any]:
        '''
        Pops (i.e. removes and returns) a value from the vault's variables, optionally decrypting it.
        Attempts to preserve metadata like comments and Jinja2 blocks.
        When `default` is set to `ThrowError`, a `KeyError` will be raised if the path does not exist.
        Else, the default value is returned if the path does not exist.
        When `with_index` is set to True, a tuple `(index_in_parent, value)` is returned (-1 if defaulted).
        Be aware that this method is experimental and may mess up comment and Jinja2 metadata.
        '''
        path = Vault._to_path(path)
        index, value = self.get(path, default=default, decrypt=decrypt, with_index=True)
        # If we did not receive the default value back, we have to delete the key and move its metadata
        if index > -1:
            parent: Indexable = self._traverse(path[:-1], decrypt=False)
            # XXX Metadata manipulation is broken
            """
            # XXX
            # When a key is deleted, all following comments (not just EOL) up to the next var will be deleted.
            # We need to move these comment tokens from key_parent.ca.items[key] to the previous item.
            # If there is not previous item, we need to merge them into key_parent.ca.comment.
            # XXX Problem we have not adressed yet:
            # When deleting a list or dict, the following comments/Jinja2 are actually part of the deepest last element's metadata, 
            # not the root elem
            if isinstance(value, dict | list):
                def _find_last_child(_path: tuple[Hashable, ...]) -> tuple[Hashable, ...]:
                    '''Finds the child of an indexable that is printed last.'''
                    _value: Any = self._traverse(_path, decrypt=False)
                    if isinstance(_value, dict) and _value:
                        return _find_last_child(_path + ( list(_value.keys())[-1], ))
                    if isinstance(_value, list) and _value:
                        return _find_last_child(_path + ( len(_value) - 1, ))
                    return _path
                _last_path: tuple[Hashable, ...] = _find_last_child(path)
                _last_parent: Indexable = self._traverse(_last_path[:-1], decrypt=False)
            else:
                _last_path = path
                _last_parent = parent
            # First, we need to check if there is a previous key we can move the metadata to
            if index > 0:
                # If the parent can hold metadata, we can assume it is ordered (CommentedMap | CommentedSeq)
                prev_key = (list(parent.keys())[index - 1]) if isinstance(parent, dict) else (parent[index - 1])
                self._move_metadata(_last_path, path[:-1] + ( prev_key, ), merge=True)
            # If there is no previous key and the key holds metadata, merge the metadata with the parent's base comment
            elif isinstance(_last_parent, CommentedMap | CommentedSeq) and path[-1] in _last_parent.ca.items:
                # Anchor #2 holds EOL comments, anchor #3 holds next-line comments (usually merged into #2 if both exist)
                # We can ignore #0 and #1 (I think)
                if _last_parent.ca.items[_last_path[-1]][2] or _last_parent.ca.items[_last_path[-1]][3]:
                    new_metadata: list = (_last_parent.ca.items[_last_path[-1]][2] or []) + (_last_parent.ca.items[_last_path[-1]][3] or [])
                    parent.ca.comment = [ parent.ca.comment[0], (parent.ca.comment[1] or []) + new_metadata ]
            """
            # Remove value
            del parent[path[-1]] # type: ignore
        return (index, value) if with_index else value

    # XXX Deprecated due to parser issues
    """
    def rename_key(self, path: DictPath, rename_to: Hashable, overwrite: bool | Type[ThrowError] = ThrowError) -> bool:
        '''
        Renames a key, preserving its position and metadata. Returns True on success. Only works for dict-like parents.

        `overwrite` controls what happens if a value is already present at the new key path:
          - `True`: Replace the existing key's value
          - `False`: Abort silently, returning False
          - `ThrowError`: Raise a KeyError if the new key path already exists
        '''
        path = Vault._to_path(path)
        parent: CommentedMap = self._traverse(path[:-1], decrypt=False)
        if not isinstance(parent, dict):
            raise TypeError('Can only rename keys in dict-like structures.')
        # Check if the old key exists
        if path[-1] not in parent:
            raise KeyError(f"Key path { '.'.join(map(str, path)) } could not be found in { self }")
        # Check if the new key already exists
        if rename_to in parent:
            if overwrite is False:
                return False
            if overwrite is ThrowError:
                raise KeyError(f"Rename target { '.'.join(map(str, path[:-1] + ( rename_to, ))) } already exists")
        # Find index of old key
        key_index: int = next(index for index, key in enumerate(parent) if key == path[-1])
        # Rename key and move metadata
        self._move_metadata(path, path[:-1] + ( rename_to, ))
        parent.insert(key_index, rename_to, parent.pop(path[-1]))
        return True

    # XXX This method is pretty much broken, as we would need to perform complex merging
    #     for the multiple comment types and parent comments
    def _move_metadata(self, old_path: DictPath, new_path: DictPath, merge: bool = False) -> None:
        '''
        Moves the metadata (i.e. comments and Jinja2) of an item to another item.
        If `merge` is set to False, the new item's metadata will be overwritten.
        Else, it will be merged with the old item's metadata (in order new, old).
        The parent of the new item has to exist already, the new item itself doesn't have to.
        '''
        old_path, new_path = Vault._to_path(old_path), Vault._to_path(new_path)
        # Get parent dict of old key, which contains the key metadata
        old_parent: Indexable = self._traverse(old_path[:-1], decrypt=False)
        # Get parent dict of new key, which will receive the key metadata
        new_parent: Indexable = self._traverse(new_path[:-1], decrypt=False)
        # If the old parent has no capability of storing metadata, return
        if not isinstance(old_parent, CommentedMap | CommentedSeq):
            return
        # Check if the old key's parent has any CA metadata for the key, else we're already done
        if old_path[-1] not in old_parent.ca.items:
            return
        # If the new parent has no capability of receiving metadata, raise an error
        if not isinstance(new_parent, CommentedMap | CommentedSeq):
            raise TypeError(f"New parent { '.'.join(map(str, new_parent)) } cannot hold any metadata")
        # Check if we should merge metadata (old is appended to new as we assume the old item comes after the new one)
        if merge and new_path[-1] in new_parent.ca.items and new_parent.ca.items[new_path[-1]]:
            # The metadata consists of a list with each item being either None, a CommentToken or a list of CommentTokens
            old_metadata: list = old_parent.ca.items.pop(old_path[-1])
            merged_metadata: list = new_parent.ca.items[new_path[-1]]
            print(merged_metadata, old_metadata)
            for index, _ in enumerate(merged_metadata):
                if old_metadata[index]:
                    _merged = merged_metadata[index]
                    _old = old_metadata[index]
                    print(_merged, _old)
                    # Direct overwrite
                    if not _merged:
                        merged_metadata[index] = _old
                    # Direct token merge if both are tokens
                    elif type(_merged) == type(_old) == CommentToken:
                        merged_metadata[index] = CommentToken(
                            value = _merged.value + _old.value,
                            start_mark = _merged.start_mark,
                            end_mark = _merged.end_mark,
                            column = _merged.column
                        )
                    # Convert to lists and merge those
                    else:
                        _merged = _merged or []
                        _merged = _merged if type(_merged) is list else [ _merged ]
                        _old = _old or []
                        _old = _old if type(_old) is list else [ _old ]
                        merged_metadata[index] = _merged + _old
            print(merged_metadata)
        else:
            # Overwrite the CA (comment anchor) metadata, which includes Jinja2 blocks
            new_parent.ca.items[new_path[-1]] = old_parent.ca.items.pop(old_path[-1])
    """

    def _traverse(self, path: DictPath, decrypt: bool = False, copy: bool = False) -> Any:
        '''
        Gets the value of the specified key path from the `Vault`'s `_data`, optionally decrypting it.
        When `copy` or `decrypt` is set to True, a deep copy of the value will be returned.
        '''
        path = cast(tuple[Hashable, ...], Vault._to_path(path))
        data: dict = self._decrypted_copy() if decrypt else (Vault._copy_data(self._data) if copy else self._data)
        def _get_child(parent: Indexable, index: Hashable) -> Any:
            if not isinstance(parent, dict | list):
                raise TypeError(f"Can only index into dict-like and list-like types, got { type(parent) } for index { index }")
            is_dict: bool = isinstance(parent, dict)
            if (is_dict and index not in parent) or (not is_dict and cast(int, index) > len(parent)):
                raise KeyError(f"Key '{ index }' of path '{ '.'.join(map(str, path)) }' could not be resolved")
            return parent[index] # type: ignore
        return reduce(_get_child, path, data)

    def _decrypted_copy(self, remove_sentinel: bool = False) -> dict:
        '''Returns a recursively decrypted deep copy of the vault data. Removing the sentinel may break comments/Jinja2.'''
        copy: CommentedMap = Vault._copy_data(self._data)
        if remove_sentinel:
            copy.pop(SENTINEL_KEY, None)
        def _decrypt_leaf(_: tuple[Hashable, ...], value: Any) -> Any:
            '''Transforms EncryptedVar leaves into decrypted strings.'''
            return self.keyring.decrypt(value.cipher) if type(value) is EncryptedVar else value
        Vault._transform_leaves(copy, _decrypt_leaf, tuple())
        return copy

    @staticmethod
    def _to_path(path: DictPath) -> tuple[Hashable, ...]:
        '''Create a tuple of dictionary keys for traversing nested dictionaries. Can be initialized with a single key or a tuple.'''
        return path if isinstance(path, tuple) else ( path, )

    # Output formats

    def as_json(self) -> str:
        '''Returns the decrypted variables of the vault as a JSON string.'''
        return json.dumps(dict(self.decrypted_vars), indent=2)

    def as_plain(self) -> str:
        '''Returns the vault in fully decrypted form as Jinja2 YAML code with the original metadata.'''
        copy: dict = self._decrypted_copy()
        yaml_content: str = self._dump_to_str(copy)
        yaml_content = Vault._remove_sentinel(yaml_content)
        return yaml_content

    def as_editable(self, with_header: bool = True) -> str:
        '''
        Returns the vault as Jinja2 YAML code with the original metadata.
        It is prepared for editing and later re-encryption with YAML tags and a static explanatory header.
        '''
        copy: CommentedMap = Vault._copy_data(self._data)
        def _convert_to_proto(path: tuple[Hashable, ...], value: Any) -> Any:
            '''Marks encrypted leaves for encryption after editing.'''
            if type(value) is not EncryptedVar:
                return value
            return ProtoEncryptedVar(self.keyring.decrypt(value.cipher), value.name or str(path[-1]))
        Vault._transform_leaves(copy, _convert_to_proto, tuple())
        yaml_content: str = self._dump_to_str(copy)
        yaml_content = Vault._remove_sentinel(yaml_content)
        # Add static header
        if with_header:
            return EDIT_MODE_HEADER + yaml_content
        return yaml_content

    def as_encrypted(self) -> str:
        '''Returns the vault as Jinja2 YAML code with the original metadata, with encrypted variables and full encryption if enabled.'''
        copy: CommentedMap = Vault._copy_data(self._data)
        yaml_content: str = self._dump_to_str(copy)
        yaml_content = Vault._remove_sentinel(yaml_content)
        if self.full_encryption:
            yaml_content = self.keyring.encrypt(yaml_content)
        return yaml_content

    @staticmethod
    def _transform_leaves(indexable: Indexable, transform_fn: Callable[[tuple[Hashable, ...], Any], Any], curr_path: tuple[Hashable, ...]) -> None:
        '''
        Runs the transform_fn on all leaves of the indexable object recursively, passing the current path and the leaf object as a tuple.
        The leaves are replaced by the result of the function call.
        '''
        if not isinstance(indexable, dict | list):
            raise Exception(f"Calling _transform_leaves on a non-indexable object is not allowed, got { type(indexable) }")
        keys: list[Hashable] = list(indexable.keys()) if isinstance(indexable, dict) else list(range(len(indexable)))
        for key in keys:
            _curr_path: tuple[Hashable, ...] = curr_path + ( key, )
            if isinstance(indexable[key], dict | list): # type: ignore
                Vault._transform_leaves(indexable[key], transform_fn, _curr_path) # type: ignore
            else:
                indexable[key] = transform_fn(_curr_path, indexable[key]) # type: ignore

    @staticmethod
    def _remove_sentinel(yaml_content: str) -> str:
        '''Removes the root sentinel key from the given raw YAML string. Returns the modified YAML.'''
        # Since the parser should put all root keys on their own line, remove (first) line containing the sentinel key
        lines: list[str] = yaml_content.split('\n')
        for index, line in enumerate(lines):
            if line.strip() == f"{ SENTINEL_KEY }:":
                lines.pop(index)
                break
        return '\n'.join(lines).strip('\n') + '\n'

    def _dump_to_str(self, data: Any) -> str:
        '''Since the YAML parser requires a stream object to dump to, this method handles text streaming.'''
        builder = StringIO()
        self._parser.dump(data, builder)
        return builder.getvalue().strip('\n') + '\n'

    @staticmethod
    def _copy_data(data: Any) -> Any:
        '''
        Create a deep copy of any data, using the object's `copy()` method for dicts and lists.
        Parser dicts and lists contain special data, and their copy function will preserve that.
        The built-in `copy.deepcopy()` would require a `__deepcopy__` method for this to work.
        Copying works for dicts and lists. Everything else is referenced normally.
        Not thread-safe.
        '''
        if (is_dict := isinstance(data, dict)) or isinstance(data, list):
            copy: Any = data.copy()
            keys = cast(dict, copy).keys() if is_dict else range(len(copy))
            for key in keys:
                copy[key] = Vault._copy_data(copy[key])
            return copy
        return data

    # Comparing to older versions of this vault

    def diff(self, prev_vault: 'Vault', context_lines: int = 3, show_filenames: bool = True) -> str:
        '''
        Generates a diff for the edit mode Jinja2 YAML vault code (from `Vault.as_editable`) of a previous vault to this one's.
        Set `context_lines` to specify how many lines of context are shown before and after the actual diff lines.
        If `show_filenames` is set to True and the vaults are `VaultFile` objects,
        the previous and current filenames will be shown in the diff header.
        '''
        # Generate filenames
        prev_filename: str = 'Previous vault'
        if show_filenames and isinstance(prev_vault, VaultFile):
            prev_filename = prev_vault.vault_path
        curr_filename: str = 'Current vault'
        if show_filenames and isinstance(self, VaultFile):
            curr_filename = self.vault_path
        # Generate diff
        return '\n'.join(
            unified_diff(
                prev_vault.as_editable().split('\n'),
                self.as_editable().split('\n'),
                fromfile = prev_filename,
                tofile = curr_filename,
                n = context_lines,
                lineterm = ''
            )
        )
    
    def changes(self, prev_vault: 'Vault') -> tuple[ChangeList, ChangeList, ChangeList, ChangeList]:
        '''
        Returns the changes between two (decrypted) vault root data structures.
        Included changes are added, removed, changed and de-encrypted keys.
        Changes are modeled as traversal paths and only minimal paths are recorded.
        Returns a tuple of (decrypted_paths, removed_paths, changed_paths, added_paths)
        where each element is a list of traversal paths.
        Note that decrypted variables will be recorded twice: In decrypted_paths and in changed_paths.
        '''
        # Prepare input and result data
        old_root: CommentedMap = prev_vault._data
        new_root: CommentedMap = self._data
        decrypted_paths: ChangeList = []
        removed_paths  : ChangeList = []
        changed_paths  : ChangeList = []
        added_paths    : ChangeList = []
        # Traverse root and find changes
        def _traverse_and_find_changes(path: tuple[Hashable, ...], old_node: Any, new_node: Any) -> None:
            '''Traverses the old and new data structures and finds changes, discarding each branch after finding a minimal path.'''
            # Type changed (possibly even decryption)
            if type(old_node) is not type(new_node):
                if type(old_node) is EncryptedVar:
                    decrypted_paths.append(path)
                changed_paths.append(path)
                return
            # Leaf value changed (or abort because this is a leaf and it stayed the same)
            if not isinstance(old_node, dict | list):
                # We have to do a special comparison for EncryptedVars as their cipher contains a random salt and can't be compared
                if type(old_node) is EncryptedVar:
                    if self.keyring.decrypt(old_node.cipher) != self.keyring.decrypt(new_node.cipher):
                        changed_paths.append(path)
                elif old_node != new_node:
                    changed_paths.append(path)
                return
            # Check for added and removed nodes in indexables and recurse
            if (is_dict := isinstance(old_node, dict)):
                keys: list[Hashable] = sorted(set(old_node.keys()).union(new_node.keys()))
            else:
                keys: list[Hashable] = list(range(max(len(old_node), len(new_node))))
            for key in keys:
                _path: tuple[Hashable, ...] = path + ( key, )
                # Check if a key has been added or removed
                if (is_dict and key in old_node and key not in new_node) or \
                   (not is_dict and cast(int, key) < len(old_node) and cast(int, key) >= len(new_node)):
                    removed_paths.append(_path)
                    continue
                if (is_dict and key in new_node and key not in old_node) or \
                   (not is_dict and cast(int, key) < len(new_node) and cast(int, key) >= len(old_node)):
                    added_paths.append(_path)
                    continue
                # Traverse subtree of node
                _traverse_and_find_changes(_path, old_node[key], new_node[key]) # type: ignore
        _traverse_and_find_changes(tuple(), old_root, new_root)
        return decrypted_paths, removed_paths, changed_paths, added_paths

    def copy(self) -> 'Vault':
        '''Create a copy of this `Vault` instance.'''
        copy = Vault('', self.keyring)
        copy._data = Vault._copy_data(self._data)
        copy.full_encryption = self.full_encryption
        copy.keyring = self.keyring
        copy._parser = self._parser
        return copy

    # Search functions

    def search_keys(self, query: str, is_regex: bool = False, as_bool: bool = False) -> bool | list[tuple[Hashable, ...]]:
        '''
        Matches query on all key names in the vault's data and returns matches or a flag signifying some matches were found.
        Non-regex queries are case-insensitive.
        '''
        matches: list[tuple[Hashable, ...]] = []
        query = str(query)
        # Match on all keys by traversing through each leaf's path and looking for matches
        def _match_keys(path: tuple[Hashable, ...], value: Any) -> Any:
            '''Checks all keys in a leaf's path for query matches.'''
            for curr_end, segment in enumerate(path, start=1):
                segment = str(segment)
                if (is_regex and re.match(query, segment)) or (not is_regex and segment.lower() == query.lower()):
                    matches.append(path[:curr_end])
            return value
        Vault._transform_leaves(self._data, _match_keys, tuple())
        # Return bool or list of matches
        return bool(matches) if as_bool else matches

    def search_leaf_values(self, query: str, is_regex: bool = False, as_bool: bool = False) -> bool | list[tuple[Hashable, ...]]:
        '''
        Matches query on all (decrypted) leaf values in the vault's data and returns matches or a flag signifying some matches were found.
        Non-regex queries are case-insensitive.
        '''
        matches: list[tuple[Hashable, ...]] = []
        query = str(query)
        # Match on all decrypted leaf values by traversing through each leaf's path and looking for matches
        def _match_decrypted_leaves(path: tuple[Hashable, ...], value: Any) -> Any:
            '''Checks the decrypted value of the current leaf for query matches.'''
            if type(value) is EncryptedVar:
                value = self.keyring.decrypt(value.cipher)
            if value is None:
                return value
            value = str(value)
            if (is_regex and re.match(query, value)) or (not is_regex and value.lower() == query.lower()):
                matches.append(path)
            return value
        Vault._transform_leaves(self._data, _match_decrypted_leaves, tuple())
        # Return bool or list of matches
        return bool(matches) if as_bool else matches

    def search_vaulttext(
        self, query: str, is_regex: bool = False, as_bool: bool = False, from_plain: bool = False, multiline: bool = False
    ) -> bool | list[MatchLocation]:
        '''
        Finds matches for the given query in the fully decrypted editable Jinja2 YAML vault code (from `Vault.as_editable`)
        and returns the match locations as tuples of ((start_line, start_col), (end_line, end_col))
        or a flag signifying some matches were found.
        The locations are relative to the `as_editable` unless you set `from_plain`, in which case `as_plain` is used.
        If `multiline` is set, a regex `.` matches newlines.
        Non-regex queries are case-insensitive.
        '''
        yaml_content: str = self.as_plain() if from_plain else self.as_editable()
        if not is_regex:
            yaml_content = yaml_content.lower()
        matches: list[MatchLocation] = []
        # Ensure the query is properly escaped if it's plain text
        pattern: str = query if is_regex else re.escape(query.lower())
        # Process all matches
        _matches = re.finditer(pattern, yaml_content, re.DOTALL) if multiline else re.finditer(pattern, yaml_content)
        for match in _matches:
            start_idx: int = match.start()
            end_idx: int = match.end()
            # Convert match indices to line and column numbers (1-indexed)
            start_line: int = yaml_content[:start_idx].count('\n') + 1
            start_col: int = start_idx - yaml_content[:start_idx].rfind('\n')
            end_line: int = yaml_content[:end_idx].count('\n') + 1
            end_col: int = end_idx - yaml_content[:end_idx].rfind('\n')
            # Add tuple of converted indices to matches
            matches.append(( ( start_line, start_col ), ( end_line, end_col ) ))
        # Return bool or list of matches
        return bool(matches) if as_bool else matches

    # Internals

    def __repr__(self) -> str:
        return f"Vault({ 'un' * (not self.full_encryption) }encrypted)"

class VaultFile(Vault):
    '''
    Wrapper around a `Vault` that handles reading from and writing to a (Jinja2 yaml) vault file on disk.
    Note that the file has to exist already at init or a `FileNotFoundError` error will be raised on loading and/or saving.
    Use the `VaultFile.create` method to create a file that doesn't exist yet with your desired encryption settings.
    '''

    def __init__(self, vault_path: str, keyring: VaultKeyring | None = None) -> None:
        '''
        Loads the contents of the specified vault file and initializes a `Vault` with them.
        If no keyring is supplied, only plain vars and content are supported.
        '''
        self.vault_path: str = os.path.abspath(vault_path)
        yaml_content: str = self._load_file_content(self.vault_path)
        super().__init__(yaml_content, keyring=keyring)

    @classmethod
    def create(
            VaultFile: Type['VaultFile'],
            path: str,
            content: str = '',
            full_encryption: bool = True,
            permissions: octal | None = None,
            keyring: VaultKeyring | None = None
        ) -> 'VaultFile':
        '''
        Creates a new vault file at the specified path. Raises a `FileExistsError` if the path is already occupied.
        If `content` is set, the vault will contain this Jinja2 yaml text instead of being empty.
        If `full_encryption` is set to True, the file will be wholly encrypted, even if empty.
        If `permissions` are set, the new file's permissions will be modified to that octal.
        If no keyring is supplied, only plain vars are supported and enabling `full_encryption` will not work.
        '''
        if os.path.exists(path):
            raise FileExistsError(f"Vault file { path } already exists")
        # Create file first and set permissions before filling in the data
        with open(path, 'w'): pass
        if permissions is not None:
            os.chmod(path, permissions)
        # Write content to file
        if full_encryption and not keyring:
            raise NoVaultKeysError(f"No vault keys available to write encrypted content to { path }")
        with open(path, 'w') as file:
            file.write(cast(VaultKeyring, keyring).encrypt(content) if full_encryption else content)
        # Create VaultFile and write content to disk
        vaultfile = VaultFile(path, keyring=keyring)
        vaultfile.full_encryption = full_encryption
        vaultfile.save()
        return vaultfile

    @classmethod
    def from_editable(VaultFile: Type['VaultFile'], prev_vault_file: 'VaultFile', edited_content: str) -> 'VaultFile':
        '''Converts a YAML vault edited from a `VaultFile.as_editable` template into a new `VaultFile`. Does not update the file on disk.'''
        # Create vault from editable, then wrap with our class and copy relevant attributes over
        vault: VaultFile = cast(VaultFile, Vault.from_editable(prev_vault_file, edited_content))
        vault.__class__ = VaultFile
        vault.vault_path = prev_vault_file.vault_path
        return vault

    def save(self) -> None:
        '''Saves the current `Vault` contents to the vault file attached to this `VaultFile`. '''
        self._save_to_file(self.vault_path, self.as_encrypted())

    def copy(self) -> 'VaultFile':
        '''Create a copy of this `VaultFile` instance.'''
        copy: VaultFile = self.from_editable(self, '')
        copy._data = VaultFile._copy_data(self._data)
        copy.full_encryption = self.full_encryption
        copy.keyring = self.keyring
        copy._parser = self._parser
        return copy

    @staticmethod
    def _load_file_content(path: str) -> str:
        '''Loads the contents of a file into a string. Throws an error if the file does not exist.'''
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Vault file { path } could not be found")
        with open(path, 'r') as file:
            return file.read()

    @staticmethod
    def _save_to_file(path: str, content: str) -> None:
        '''Saves the given content to a file. Throws an error if the file does not exist.'''
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Vault file { path } could not be found")
        with open(path, 'w') as file:
            file.write(content)

    def __repr__(self) -> str:
        return f"VaultFile({ self.vault_path }, { 'un' * (not self.full_encryption) }encrypted)"
