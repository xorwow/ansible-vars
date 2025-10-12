# Run from project dir via `PYTHONPATH=src pytest`

from io import StringIO
from os import stat, unlink as rm_file
from json import loads as load_json
from typing import TypeAlias, Any
from pathlib import Path

from ruamel.yaml import YAML

from ansible_vars.vault import VaultFile, Vault, EncryptedVar
from ansible_vars.vault_crypt import VaultKeyring, VaultKey
from ansible_vars.constants import APPEND_SENTINEL

JSONObject: TypeAlias = Any

class TestVaultCrypt:

    PLAINTEXT: str = 'plaintext' # also used as passphrase
    FIXED_SALT: str = 'a' * 32
    CIPHERTEXT: str = '$ANSIBLE_VAULT;1.2;AES256;testid\n36313631363136313631363136313631363136313631363136313631363136313631363136313631\n3631363136313631363136313631363136313631363136310a313237663761353633656137653065\n32656664313566373062383839343461353163363831313666343763313738616336393261303361\n3239646238323033300a303163663861326632626335373030666436303266653739306133396239\n3439'
    VAULT_ID: str = 'testid'

    def test_create_key_from_str(self) -> None:
        key: VaultKey = VaultKey(self.PLAINTEXT, vault_id=self.VAULT_ID)
        assert key.passphrase == self.PLAINTEXT, 'decoded passphrase doesn\'t match loaded passphrase'

    def test_create_simple_keyring(self) -> None:
        key: VaultKey = VaultKey(self.PLAINTEXT, vault_id=self.VAULT_ID)
        keyring: VaultKeyring = VaultKeyring(keys=[ key ], detect_available_keys=False)
        assert keyring.key_by_id(self.VAULT_ID) == key, 'keyring doesn\'t contain added key'
        assert keyring.encryption_key == key, 'keyring assigned wrong encryption key'

    def test_detection_by_config_path_using_passfile(self, tmp_path: Path) -> None:
        # Create a file containing the passphrase
        pass_file_relpath: str = 'vaultpass'
        pass_file_path: Path = tmp_path.joinpath(pass_file_relpath)
        with open(pass_file_path, 'w') as f:
            f.write(self.PLAINTEXT)
        # Create an Ansible config pointing to the passphrase file (by its relative path, to test directory resolution)
        config_path: Path = tmp_path.joinpath('ansible.cfg')
        with open(config_path, 'w') as f:
            f.write(f"[defaults]\nvault_identity_list={ self.VAULT_ID }@{ pass_file_relpath }")
        # Try to load the secret via the config
        keyring: VaultKeyring = VaultKeyring(detect_available_keys=True, detection_source=str(config_path))
        assert len(keyring.keys) == 1, 'keyring did not detect any keys or too many'
        assert keyring.keys[0].id == self.VAULT_ID, 'keyring extracted wrong vault ID'
        assert keyring.keys[0].passphrase == self.PLAINTEXT, 'keyring loaded wrong passphrase'

    def test_detection_by_vault_id_using_passfile(self, tmp_path: Path) -> None:
        # Create a file containing the passphrase
        pass_file_path: Path = tmp_path.joinpath('vaultpass')
        with open(pass_file_path, 'w') as f:
            f.write(self.PLAINTEXT)
        # Try to load the secret via the config by directly supplying vault IDs
        vault_ids: list[str] = [ f"{ self.VAULT_ID }@{ pass_file_path }" ] # can't resolve relative paths without base dir info
        keyring: VaultKeyring = VaultKeyring(detect_available_keys=True, detection_source=vault_ids)
        assert len(keyring.keys) == 1, 'keyring did not detect any keys or too many'
        assert keyring.keys[0].id == self.VAULT_ID, 'keyring extracted wrong vault ID'
        assert keyring.keys[0].passphrase == self.PLAINTEXT, 'keyring loaded wrong passphrase'

    def test_encryption_check(self) -> None:
        assert VaultKey.is_encrypted(self.CIPHERTEXT), 'expected ciphertext to be detected as encrypted'
        assert not VaultKey.is_encrypted(self.PLAINTEXT), 'expected plaintext to be detected as plain'

    def test_encrypt(self) -> None:
        key: VaultKey = VaultKey(self.PLAINTEXT, vault_id=self.VAULT_ID)
        cipher: str = key.encrypt(self.PLAINTEXT, salt=self.FIXED_SALT)
        assert cipher == self.CIPHERTEXT, 'encrypted plaintext does not match expected cipher'

    def test_decrypt(self) -> None:
        key: VaultKey = VaultKey(self.PLAINTEXT, vault_id=self.VAULT_ID)
        plaintext: str = key.decrypt(self.CIPHERTEXT)
        assert plaintext == self.PLAINTEXT, 'decrypted ciphertext does not match expected plaintext'

    def test_find_decryption_key(self) -> None:
        keys: list[VaultKey] = [
            VaultKey('INCORRECT_KEY_0', vault_id='wrong0'),
            VaultKey('INCORRECT_KEY_1', vault_id='wrong1'),
            VaultKey(self.PLAINTEXT, vault_id=self.VAULT_ID)
        ]
        keyring: VaultKeyring = VaultKeyring(keys=keys, detect_available_keys=False)
        assert keyring.decrypt(self.CIPHERTEXT) == self.PLAINTEXT, 'keyring did not find correct decryption key'

class TestVault:

    KEYRING: VaultKeyring = VaultKeyring(
        [ VaultKey('passphrase', vault_id='testid') ],
        default_salt=('a' * 32), detect_available_keys=False
    )

    def test_file_load_save(self, tmp_path: Path) -> None:
        sentinel: str = 'XXX_TEST_STRING_XXX'
        vault_path: Path = tmp_path.joinpath('vault.yml')
        with open(vault_path, 'w+') as f:
            # Write test value to file
            f.write(f"a: '{ sentinel }'")
            f.flush()
            f.seek(0)
            assert sentinel in f.read(), 'expected value in file (manual write)'
        # Load file to vault
        vault: VaultFile = VaultFile(str(vault_path), self.KEYRING)
        with open(vault_path, 'w+') as f:
            # Empty file
            f.write('')
            f.flush()
            f.seek(0)
            assert sentinel not in f.read(), 'expected file to be empty'
        # Save vault to file
        vault.save()
        with open(vault_path) as f:
            assert sentinel in f.read(), 'expected value in file (vault write)'
    
    def test_file_create(self, tmp_path: Path) -> None:
        plain_content: str = '#test\n'
        encrypted_content: str = self.KEYRING.encrypt(plain_content)
        vault_path: Path = tmp_path.joinpath('vault.yml')
        # Test vault with full encryption from plain content
        vault: VaultFile = VaultFile.create(str(vault_path), content=plain_content, full_encryption=True, keyring=self.KEYRING)
        exported: str = vault.as_encrypted().replace(' ', '')
        assert vault.full_encryption, 'expected full encryption to be active'
        assert plain_content not in exported, 'found plain content in a fully encrypted export'
        assert encrypted_content in exported, 'could not find encrypted content in export'
        # Test vault with no encryption from encrypted content
        rm_file(vault_path)
        vault = VaultFile.create(str(vault_path), content=encrypted_content, full_encryption=False, keyring=self.KEYRING)
        exported = vault.as_encrypted().replace(' ', '')
        assert not vault.full_encryption, 'expected full encryption to be disabled'
        assert plain_content in exported, 'could not find plain content in export'
        assert encrypted_content not in exported, 'found encrypted content in a plain export'
        # Test vault with custom permissions
        rm_file(vault_path)
        vault = VaultFile.create(str(vault_path), full_encryption=False, permissions=0o640)
        assert str(oct(stat(vault_path).st_mode))[-3:] == '640', 'expected 640 file permissions'

    def test_file_copy(self, tmp_path: Path) -> None: # also tests Vault.copy, which is a subset of the VaultFile.copy
        vault_path: Path = tmp_path.joinpath('vault.yml')
        vault_orig: VaultFile = VaultFile.create(str(vault_path), full_encryption=False, keyring=self.KEYRING)
        vault_orig.set('a', [ 1, 2, 3 ])
        vault_copy: VaultFile = vault_orig.copy()
        assert vault_copy.vault_path == vault_orig.vault_path, 'path should be identical'
        assert vault_copy.keyring is vault_orig.keyring, 'keyrings should be the same reference'
        assert vault_copy.full_encryption == vault_orig.full_encryption, 'encryption setting should be identical'
        assert vault_copy._parser is vault_orig._parser, 'parsers should be the same reference'
        assert vault_copy._data is not vault_orig._data, 'data should not be the same reference'
        assert vault_copy._data['a'] is not vault_orig._data['a'], 'lists should not be the same reference'
        assert vault_copy._data['a'] == vault_orig._data['a'], 'lists should have the same content'

    def test_load_comments_only(self) -> None:
        comment: str = '# this is a comment'
        vault: Vault = Vault(comment, keyring=self.KEYRING)
        assert not vault.full_encryption, 'expected vault to be plain'
        assert not vault.decrypted_vars, 'expected vault to have no data'
        assert comment in vault.as_plain(), 'comment did not survive loading'

    def test_load_fully_encrypted(self) -> None:
        vault: Vault = Vault(self.KEYRING.encrypt('test_var: test'), keyring=self.KEYRING)
        decrypted_vars: dict[str, Any] = vault.decrypted_vars
        assert vault.full_encryption, 'vault did not detect full encryption'
        assert 'test_var' in decrypted_vars, 'vault did not load test var'
        assert decrypted_vars['test_var'] == 'test', 'vault did not load correct value for test var'

    def test_decrypted_vars(self) -> None:
        example_vars: dict = {
            'str_test': self.KEYRING.encrypt('test'),
            'deep_test': [ self.KEYRING.encrypt('a'), self.KEYRING.encrypt('b') ]
        }
        vault: Vault = self._create_simple_vault(example_vars)
        decrypted_vars: dict[str, Any] = vault.decrypted_vars
        assert len(decrypted_vars) == len(example_vars), 'vault did not load correct amount of vars'
        assert decrypted_vars['str_test'] == 'test', 'string was not decrypted correctly'
        assert decrypted_vars['deep_test'] == [ 'a', 'b' ], 'child strings were not decrypted correctly'

    def test_has_path(self) -> None:
        vault: Vault = self._create_simple_vault({ 'a': [ 'x' ] })
        assert vault.has(( 'a', 0 )), 'expected path to exist'
        assert not vault.has(( 'a', 1 )), 'expected path not to exist'

    def test_get_raw(self) -> None:
        ciphertext: str = self.KEYRING.encrypt('x')
        vault: Vault = self._create_simple_vault({ 'a': [ ciphertext ] })
        got: Any = vault.get(( 'a', 0 ), default=None, decrypt=False)
        assert isinstance(got, EncryptedVar) and got.cipher == ciphertext, 'expected encrypted variable'

    def test_get_decrypted_simple(self) -> None:
        plaintext: str = 'x'
        vault: Vault = self._create_simple_vault({ 'a': [ self.KEYRING.encrypt(plaintext) ] })
        got: Any = vault.get(( 'a', 0 ), default=None, decrypt=True)
        assert got, 'expected path to exist'
        assert got == plaintext, 'expected decrypted variable'

    def test_get_decrypted_deep(self) -> None:
        plaintext: str = 'x'
        vault: Vault = self._create_simple_vault({ 'a': { 'b': [ self.KEYRING.encrypt(plaintext) ] } })
        got: Any = vault.get(( 'a', 'b' ), default=None, decrypt=True)
        assert got, 'expected path to exist'
        assert isinstance(got, list) and len(got) == 1, 'expected to find list'
        assert got[0] == plaintext, 'expected decrypted variable in list'

    def test_get_with_index(self) -> None:
        value: str = 'x'
        vault: Vault = self._create_simple_vault({ 'a': value })
        got: tuple[int, Any] = vault.get('a', with_index=True)
        assert got[0] == 0, 'expected correct index'
        assert got[1] == value, 'expected correct value'
        got = vault.get('b', default=None, with_index=True)
        assert got[0] == -1, 'expected default index'
        assert got[1] is None, 'expected default value'

    def test_set_value_without_keyring(self) -> None:
        vault: Vault = Vault.create('', full_encryption=False, keyring=None)
        value: str = 'x'
        vault.set('a', value)
        assert vault._data['a'] == value, 'expected vault data to contain plain value'

    def test_set_list_entry(self) -> None:
        vault: Vault = self._create_simple_vault()
        vault.set('a', [ 1 ])
        got: Any = vault.get('a')
        assert isinstance(got, list) and len(got) == 1, 'expected vault data to contain list'
        # Add item to list
        vault.set(( 'a', APPEND_SENTINEL ), 2)
        got = vault.get('a')
        assert len(got) == 2 and got[1] == 2, 'expected new value in list'

    def test_set_create_parents(self) -> None:
        vault: Vault = self._create_simple_vault()
        value: str = 'x'
        could_set: bool = vault.set(( 'a', 'b' ), value, create_parents=False)
        assert not could_set, 'should not be able to set value with missing parents'
        assert not vault.decrypted_vars, 'vault should be empty'
        could_set = vault.set(( 'a', 'b' ), value, create_parents=True)
        assert could_set, 'should be able to set nested value'
        assert 'a' in vault._data and 'b' in vault._data['a'], 'expected new path to exist'
        assert vault._data['a']['b'] == value, 'expected nested value to be set'

    def test_set_overwrite(self) -> None:
        old_value: str = 'x'
        new_value: str = 'y'
        vault: Vault = self._create_simple_vault({ 'a': old_value })
        could_set: bool = vault.set('a', new_value, overwrite=False)
        assert not could_set and vault.get('a') == old_value, 'should not be able to overwrite value'
        could_set = vault.set('a', new_value, overwrite=True)
        assert could_set and vault.get('a') == new_value, 'expected overwritten value'

    def test_set_encrypted_simple(self) -> None:
        plaintext: str = 'x'
        ciphertext: str = self.KEYRING.encrypt(plaintext)
        vault: Vault = self._create_simple_vault()
        vault.set('a', plaintext, encrypt=True)
        got: Any = vault.get('a')
        assert isinstance(got, EncryptedVar) and got.cipher == ciphertext, 'expected value to be encrypted'

    def test_set_encrypted_deep(self) -> None:
        plaintext: str = 'x'
        ciphertext: str = self.KEYRING.encrypt(plaintext)
        vault: Vault = self._create_simple_vault()
        vault.set('a', { 'b': [ plaintext ] }, encrypt=True)
        got: Any = vault.get(( 'a', 'b' ))
        assert isinstance(got, list) and len(got) == 1, 'expected list to be added to data'
        assert isinstance(got[0], EncryptedVar) and got[0].cipher == ciphertext, 'expected value to be recursively encrypted'

    def test_pop(self) -> None:
        value: str = 'x'
        vault: Vault = self._create_simple_vault({ 'a': value })
        assert 'a' in vault._data and vault._data['a'] == value, 'expected value to be in data'
        assert vault.pop('a', default=None) == value, 'pop should return value'
        assert 'a' not in vault._data, 'pop should have removed path'
        assert vault.pop('a', default=None) is None, 'pop should not work twice'

    def test_export_plain(self) -> None:
        plaintext: str = 'XXX_TEST_STRING_XXX'
        ciphertext: str = self.KEYRING.encrypt(plaintext)
        vault: Vault = self._create_simple_vault({ 'a': ciphertext })
        exported: str = vault.as_plain().replace(' ', '')
        assert ciphertext not in exported, 'export should be decrypted'
        assert plaintext in exported, 'export should contain plain value'

    def test_export_encrypted(self) -> None:
        plaintext: str = 'XXX_TEST_STRING_XXX'
        ciphertext: str = self.KEYRING.encrypt(plaintext)
        vault: Vault = self._create_simple_vault({ 'a': ciphertext })
        exported: str = vault.as_encrypted().replace(' ', '')
        assert plaintext not in exported, 'export should be encrypted'
        assert ciphertext in exported, 'export should contain encrypted value'

    def test_export_full_encryption(self) -> None:
        plaintext: str = 'XXX_TEST_STRING_XXX'
        ciphertext: str = self.KEYRING.encrypt(plaintext)
        vault: Vault = self._create_simple_vault({ 'a': plaintext })
        vault.full_encryption = True
        exported: str = vault.as_encrypted().replace(' ', '')
        assert plaintext not in exported and ciphertext not in exported, 'export should not contain value directly'
        assert VaultKey.is_encrypted(exported), 'export should be fully encrypted'

    def test_export_json(self) -> None:
        plaintext: str = 'XXX_TEST_STRING_XXX'
        ciphertext: str = self.KEYRING.encrypt(plaintext)
        vault: Vault = self._create_simple_vault({ 'a': ciphertext })
        exported: str = vault.as_json()
        data: JSONObject = load_json(exported)
        assert isinstance(data, dict), 'export should always be a dict'
        assert 'a' in data and data['a'] == plaintext, 'export should contain plain value'

    def test_export_import_editable(self) -> None:
        key: str = 'MY_VAR'
        value: str = 'MY_VALUE'
        vault: Vault = self._create_simple_vault({ key: value })
        editable: str = vault.as_editable(with_header=False)
        assert key in editable and value in editable, 'expected example var in editable'
        editable += '\nx: 1\ny: !enc 2'
        vault = Vault.from_editable(vault, editable)
        assert key in vault._data and vault._data[key] == value, 'expected original value to survive'
        assert 'x' in vault._data and vault._data['x'] == 1, 'expected plain value to be loaded'
        got: Any = vault.get('y', default=None, decrypt=False)
        assert isinstance(got, EncryptedVar) and got.cipher == self.KEYRING.encrypt('2'), 'expected !enc value to be encrypted'

    def test_diff(self) -> None:
        old_vault: Vault = self._create_simple_vault({ 'a': 'x', 'b': 'y' })
        new_vault: Vault = self._create_simple_vault({ 'b': 'y', 'c': 'z' })
        diff: str | None = new_vault.diff(old_vault)
        assert diff, 'expected a diff for two differing vaults'
        diff_lines: list[str] = list(filter(
            lambda line: not (line.startswith('---') or line.startswith('+++')),
            diff.split('\n')
        ))
        assert sum( int(line.startswith('-')) for line in diff_lines ) == 1, 'expected one removal'
        assert any( line.startswith('-') and 'a' in line for line in diff_lines ), 'expected key "a" to be removed'
        assert sum( int(line.startswith('+')) for line in diff_lines ) == 1, 'expected one addition'
        assert any( line.startswith('+') and 'c' in line for line in diff_lines ), 'expected key "c" to be added'
        assert old_vault.diff(old_vault) is None, 'expected empty diff for identical vaults'

    def test_changes(self) -> None:
        old_vault: Vault = self._create_simple_vault({ 'a': 'x', 'b': 'y', 'cipher': self.KEYRING.encrypt('secret') })
        new_vault: Vault = self._create_simple_vault({ 'b': 'Y', 'c': 'z', 'cipher': 'secret' })
        decrypted, removed, changed, added = new_vault.changes(old_vault)
        assert decrypted == [ ( 'cipher', ) ], 'key "cipher" has been decrypted'
        assert removed == [ ( 'a', ) ], 'key "a" has been removed'
        assert sorted(changed) == [ ( 'b', ), ( 'cipher', ) ], 'keys "b" and "cipher" have been modified'
        assert added == [ ( 'c', ) ], 'key "c" has been added'

    def test_search_key(self) -> None:
        vault: Vault = self._create_simple_vault({ 'aaa': 'x', 'bbb': 'y' })
        found: Any = vault.search_keys('a+', is_regex=True)
        assert isinstance(found, list) and len(found) == 1 and found == [ ( 'aaa', ) ], 'expected to find key "aaa" with regex'
        found = vault.search_keys('bbb', is_regex=False)
        assert isinstance(found, list) and len(found) == 1 and found == [ ( 'bbb', ) ], 'expected to find key "bbb"'
        found = vault.search_keys('ccc', as_bool=True)
        assert found is False, 'expected not to find any key "ccc"'

    def test_search_value(self) -> None:
        vault: Vault = self._create_simple_vault({ 'a': 'xxx', 'b': 'yyy' })
        found: Any = vault.search_leaf_values('x+', is_regex=True)
        assert isinstance(found, list) and len(found) == 1 and found == [ ( 'a', ) ], 'expected to find key "a" with regex'
        found = vault.search_leaf_values('yyy', is_regex=False)
        assert isinstance(found, list) and len(found) == 1 and found == [ ( 'b', ) ], 'expected to find key "b"'
        found = vault.search_leaf_values('zzz', as_bool=True)
        assert found is False, 'expected not to find any value "zzz"'

    def test_search_text(self) -> None:
        vault: Vault = self._create_simple_vault({ 'TEST_KEY': 'TEST_VALUE' })
        found: Any = vault.search_vaulttext('TEST_K[A-Z]+', is_regex=True, from_plain=True)
        assert isinstance(found, list) and len(found) == 1 and found == [ ( ( 1, 1 ), ( 1, 9 ) ) ], 'expected match on line 1'
        found = vault.search_vaulttext('XXX', as_bool=True)
        assert found is False, 'expected not to find string "XXX"'

    def _create_simple_vault(self, vars: dict[str, JSONObject] | None = None) -> Vault:
        '''Creates a vault from the JSON representation of the given vars (of empty if no vars are supplied).'''
        with StringIO() as s:
            if vars:
                YAML().dump(vars, s)
            content: str = s.getvalue()
        content = content.replace('"$ANSIBLE_VAULT', '!vault "$ANSIBLE_VAULT') # hack for adding vault tags to encrypted values
        return Vault(content, keyring=self.KEYRING)
