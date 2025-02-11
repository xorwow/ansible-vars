# Helpers for ansible-vars

# Standard library imports
import os, atexit
from glob import glob
from pathlib import Path
from functools import wraps
from datetime import datetime
from typing import Callable
from getpass import getuser as sys_user
from shutil import copytree, rmtree, copy2, move

# External library imports
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver
from watchdog.events import FileSystemEventHandler, \
    DirCreatedEvent, DirDeletedEvent, DirMovedEvent, DirModifiedEvent, \
    FileCreatedEvent, FileDeletedEvent, FileMovedEvent, FileModifiedEvent

# Internal module imports
from .vault import Vault, VaultFile
from .vault_crypt import VaultKey, VaultKeyring
from .constants import DEFAULT_PLAIN_LOGNAME

# Diff logging

class DiffLogger():
    '''Generates log entries detailing how a vault changed over time.'''

    def __init__(self) -> None:
        '''Create a new `DiffLogger`.'''
        pass

    def make_log_entry(self, prev_vault: Vault, curr_vault: Vault, comment: str = '', force: bool = False) -> str | None:
        '''
        Formats a YAML-friendly log entry with data about the current and previous vault and the changes between them, then returns it.
        If no changes happened, None is returned, unless you set `force` to True.
        You can specify an optional comment string which will be included.
        '''
        # Check if any changes happened
        diff: list[str] = curr_vault.diff(prev_vault, context_lines=0, show_filenames=True).split('\n')
        if not force and not diff:
            return None
        # Build entry
        OUTER_SEP: str = '=' * 48
        lines: list[str] = [ OUTER_SEP ]
        # Vault info
        timestamp: datetime = datetime.now().astimezone()
        timezone: str = str(timestamp.tzinfo or 'UTC')
        lines += [ f"OLD VAULT { prev_vault }", f"NEW VAULT { curr_vault }", f"TIMESTAMP { timestamp } ({ timezone })", f"USER { sys_user() }" ]
        # Comment
        if comment:
            lines += [ f"COMMENT {comment}" ]
        lines += [ OUTER_SEP ]
        # Diff
        lines.append('DIFF')
        if diff:
            lines += diff
        else:
            lines.append('No changes.')
        #lines.append(OUTER_SEP)
        return '\n'.join([ f"#│  { line }" for line in lines ])

class DiffFileLogger(DiffLogger):
    '''Generates log entries detailing how a vault changed over time and writes them to a vault-encrypted log file.'''

    def __init__(self, log_path: str, key_or_keyring: VaultKey | VaultKeyring | None, plain: bool = False) -> None:
        '''
        Create a new `DiffLogger` that appends changes to a vault-encrypted file. The file is created if it does not exist.
        The logfile is encrypted using the passed (keyring's) encryption key (note that the content is not in YAML syntax).
        If a directory is passed instead of a file path, the filename will be inferred from the key's vault ID
        using the `DiffFileLogger.generate_filename_from_key` method.

        If `plain` is set to True, the log will be saved in an unencrypted form.
        Do not mix encrypted and unencrypted logs in the same `log_path`.
        If a filename is generated in plaintext mode, it is set to `constants.DEFAULT_PLAIN_LOGNAME`.
        !!BEWARE!! Information may get leaked if encrypted vault changes are logged in plaintext. Only use this feature
        for plaintext vars/vault files.
        '''
        self.log_path: str = os.path.abspath(log_path)
        # Create keyring if necessary
        if type(key_or_keyring) is VaultKey:
            self.keyring: VaultKeyring = VaultKeyring([ key_or_keyring ], detect_available_keys=False)
        elif type(key_or_keyring) is VaultKeyring:
            self.keyring: VaultKeyring = key_or_keyring
        else:
            self.keyring = VaultKeyring([], detect_available_keys=False)
        # Check if we should write plain data
        self.plain_mode: bool = plain
        # Create logfile if it doesn't exist yet
        self._create_logfile()
        super().__init__()

    @staticmethod
    def generate_filename_from_key(key_or_keyring: VaultKey | VaultKeyring) -> str:
        '''Generates a logfile name based on the vault ID of the given (keyring's) encryption key.'''
        # Create keyring if necessary
        if type(key_or_keyring) is VaultKey:
            keyring: VaultKeyring = VaultKeyring([ key_or_keyring ], detect_available_keys=False)
        else:
            keyring: VaultKeyring = key_or_keyring # type: ignore
        # Generate default name
        return f"vault_changelog_{ keyring.encryption_key.id }.vault"

    def log_changes(self, vault: Vault, comment: str = '', force: bool = False, enable: bool = True) -> Callable:
        '''
        Decorator for methods that modify a vault object. Does nothing if `enable` is set to False.
        Creates a log entry with data about the vault and the changes between before and after the call and appends it to the logfile.
        If no changes happened, no entry is written, unless you set `force` to True.
        You can specify an optional comment string which will be included.
        Use the `add_log_entry` method directly if you'd like to compare two different `Vault` objects instead.
        '''
        def decorator(wrapped_function: Callable):
            if not enable:
                return wrapped_function
            @wraps(wrapped_function)
            def wrapper(*args, **kw_args):
                prev_vault: Vault = vault.copy()
                res = wrapped_function(*args, **kw_args)
                self.add_log_entry(prev_vault, vault, comment=comment, force=force)
                return res
            return wrapper
        return decorator

    def add_log_entry(self, prev_vault: Vault, curr_vault: Vault, comment: str = '', force: bool = False) -> None:
        '''
        Creates a log entry with data about the current and previous vault and the changes between them and appends it to the logfile.
        If no changes happened, no entry is written, unless you set `force` to True.
        You can specify an optional comment string which will be included.
        '''
        entry: str | None = self.make_log_entry(prev_vault, curr_vault, comment=comment, force=force)
        if entry:
            with open(self.log_path, 'r+') as file:
                # Get existing content
                old_content: str = file.read()
                if not self.plain_mode:
                    old_content = self.keyring.decrypt(old_content)
                elif VaultKey.is_encrypted(old_content):
                    raise ValueError(f"File { self.log_path } is encrypted but we want to write plaintext data")
                # Extend content with new entry
                new_content: str = old_content + ('\n\n\n' * bool(old_content)) + entry
                if not self.plain_mode:
                    new_content = self.keyring.encrypt(new_content)
                # Overwrite file
                file.seek(0)
                file.truncate()
                file.write(new_content)

    def _create_logfile(self) -> None:
        '''Creates the logfile if it does not exist yet. If the current `log_path` is a directory, a file is created in it.'''
        if os.path.isdir(self.log_path):
            filename: str = DEFAULT_PLAIN_LOGNAME if self.plain_mode else DiffFileLogger.generate_filename_from_key(self.keyring)
            self.log_path = os.path.join(self.log_path, filename)
        if os.path.isfile(self.log_path):
            return
        with open(self.log_path, 'w') as file:
            file.write('' if self.plain_mode else self.keyring.encrypt(''))

# File daemon

class VaultDaemon(FileSystemEventHandler):
    '''Tracks and mirrors (some) filesystem changes from a source file/directory to a target file/directory, decrypting vaults in the target(s).'''

    def __init__(
        self, source_path: str, target_path: str, keyring: VaultKeyring, recurse: bool = True,
        error_callback: Callable = print, debug_out: Callable = print
    ) -> None:
        '''
        Mirrors (some) filesystem changes from the source to the target, decrypting any encountered vaults in the target.
        The source can either be a single file or a directory. The target must match this.
        Directories are synced recursively when `recurse` is set to True.
        If a source file can't be parsed as a vault, it is copied as-is.
        A keyring is required to decrypt vaults (the keyring may be empty if no fully or partially encrypted vaults are expected).

        Filesystem event errors are not raised directly, but passed to a callback function (`error_callback`) with the following parameters:
        - `daemon`: This `VaultDaemon` instance
        - `operation`: The performed operation (string, `create` / `delete` / `modify` / `move`)
        - `error`: The caught exception
        Other errors are raised as normal. This is done so possibly irrelevant filesystem errors (failed copy, ...) don't crash the whole daemon.
        By default, the callback function prints the error.

        Debug output is passed to a debug function (`debug_out`). By default, the function prints the message.

        Mirrored changes are:
        - Created files/directories in the source
        - Deleted files/directories in the source
        - Modified files in the source (only copies content changes, not metadata)
        - Files/Directories which were moved within the source (moves outside of the scope are handled as creation/deletion)
        '''
        source_path = os.path.abspath(source_path)
        target_path = os.path.abspath(target_path)
        is_file: bool = os.path.isfile(source_path)
        if is_file != os.path.isfile(target_path):
            raise TypeError(f"Source and target must either both be a file or both be a directory: { self }")
        # Prepare paths: We can only observe directories, so we specify a source/target file individually
        self.source_dir: str = os.path.dirname(source_path) if is_file else source_path
        self.target_dir: str = os.path.dirname(target_path) if is_file else target_path
        self.source_file: str | None = source_path if is_file else None
        self.target_file: str | None = target_path if is_file else None
        # Other vars
        self.keyring: VaultKeyring = keyring
        self.error: Callable = lambda op, err: error_callback(self, op, err)
        self.debug: Callable = lambda msg: debug_out(self, msg)
        self.recurse: bool = recurse
        # Schedule one observer for each sync direction
        self.debug(f"Initializing { self }")
        self.observer: BaseObserver = Observer()
        self.observer.schedule(self, self.source_dir, recursive=recurse)

    def start(self, stop_on_exit: bool = True) -> None:
        '''
        Starts the daemon. This copies the decrypted source file(s) to the target directory, overwriting any existing files.
        The source(s) is/are then watched for changes, which are mirrored to the target.
        When `stop_on_exit` is set to True, the daemon will automatically be stopped when the program exits.
        This function creates a new thread, which runs parallel to the main thread. Use `<this>.observer.join()` to run the thread as blocking.
        '''
        self.debug(f"Starting { self }")
        self.debug(f"Creating target and copying file(s)")
        # Create copy of source in target
        os.makedirs(self.target_dir, exist_ok=True)
        # Only sync one file
        if self.source_file:
            copy2(self.source_file, self.target_file, follow_symlinks=True) # type: ignore
        # Sync dir recursively
        elif self.recurse:
            copytree(self.source_dir, self.target_dir, symlinks=True, dirs_exist_ok=True, ignore_dangling_symlinks=True)
        # Sync flat dir
        else:
            def _ignore_subdirs(parent: str, children: list[str]) -> set:
                return { child for child in children if os.path.isdir(os.path.join(parent, child)) }
            copytree(self.source_dir, self.target_dir, ignore=_ignore_subdirs, symlinks=True, dirs_exist_ok=True, ignore_dangling_symlinks=True)
        # Find and decrypt our copied vault files in target
        def _decrypt_inplace(path: str) -> None:
            '''Decrypts a file in-place if it is a vault.'''
            try:
                vault = VaultFile(path, keyring=self.keyring)
                self.debug(f"Detected vault { os.path.join(self.source_dir, os.path.relpath(path, self.target_dir)) }")
                with open(path, 'w') as file:
                    file.write(vault.as_editable(with_header=False))
            except: pass
        if self.target_file:
            _decrypt_inplace(self.target_file)
        else:
            paths: list[str] = glob(os.path.join(self.target_dir, '**' * self.recurse, '*'), recursive=self.recurse, include_hidden=True)
            [ _decrypt_inplace(file) for file in paths if os.path.isfile(file) ]
        # Observe changes in source
        if stop_on_exit:
            atexit.register(self.stop)
        self.debug(f"Watching for changes in { self.source_dir }")
        self.observer.start()

    def stop(self, delete: bool = True) -> None:
        '''Stops the daemon. If `delete` is set to True, the target file(s) will be deleted.'''
        self.debug(f"Stopping { self }")
        self.observer.stop()
        if delete:
            if self.target_file:
                os.unlink(self.target_file)
            else:
                rmtree(self.target_dir, ignore_errors=True)

    def on_created(self, event: DirCreatedEvent | FileCreatedEvent) -> None:
        '''
        Filesystem hook for a created source path.
        Copies the file/directory to the corresponding target path, in decrypted form if it is a vault-like file.
        '''
        self.debug(f"Captured event: { event }")
        try:
            source_path: str = event.src_path.decode('utf-8') if type(event.src_path) is bytes else event.src_path # type: ignore
            target_path: str = os.path.join(self.target_dir, os.path.relpath(source_path, self.source_dir))
            # Ignore parent modifications if we're watching a single file
            if self.source_file and source_path != self.source_file:
                self.debug('Event ignored (only watching one file, parent updates are irrelevant)')
                return
            # Create directory
            if type(event) is DirCreatedEvent:
                os.makedirs(target_path, mode=0o700, exist_ok=True)
                self.debug(f"Created directory { target_path }")
            # Create decrypted copy of file
            else:
                with open(source_path) as src:
                    content: str = src.read()
                with open(target_path, 'w') as tgt:
                    try:
                        tgt.write(Vault(content, keyring=self.keyring).as_plain())
                        self.debug(f"Created/Updated file { target_path } from vault contents")
                    except:
                        tgt.write(content)
                        self.debug(f"Created/Updated file { target_path } from plain contents")
        except Exception as e:
            self.error('create', e)

    def on_deleted(self, event: DirDeletedEvent | FileDeletedEvent) -> None:
        '''Filesystem hook for a deleted source path. Deletes the corresponding target path.'''
        self.debug(f"Captured event: { event }")
        try:
            source_path: str = event.src_path.decode('utf-8') if type(event.src_path) is bytes else event.src_path # type: ignore
            target_path: str = os.path.join(self.target_dir, os.path.relpath(source_path, self.source_dir))
            # Ignore parent modifications if we're watching a single file
            if self.source_file and source_path != self.source_file:
                self.debug('Event ignored (only watching one file, parent updates are irrelevant)')
                return
            # Delete file or directory
            if type(event) is FileDeletedEvent:
                os.unlink(target_path)
                self.debug(f"Deleted file { target_path }")
            else:
                rmtree(target_path, ignore_errors=True)
                self.debug(f"Deleted directory { target_path }")
        except Exception as e:
            self.error('delete', e)

    def on_moved(self, event: DirMovedEvent | FileMovedEvent) -> None:
        '''
        Filesystem hook for a moved source path. Moves the corresponding target path by the same relative path delta.
        This is only called for a path moved within the observed source directory.
        For out-of-scope moves, `on_created` or `on_deleted` is called.
        '''
        self.debug(f"Captured event: { event }")
        try:
            source_path: str = event.src_path.decode('utf-8') if type(event.src_path) is bytes else event.src_path # type: ignore
            new_source_path: str = event.dest_path.decode('utf-8') if type(event.dest_path) is bytes else event.dest_path # type: ignore
            target_path: str = os.path.join(self.target_dir, os.path.relpath(source_path, self.source_dir))
            new_target_path: str = os.path.join(self.target_dir, os.path.relpath(new_source_path, self.source_dir))
            # Ignore parent modifications if we're watching a single file
            if self.source_file and self.source_file not in ( source_path, new_source_path ):
                self.debug('Event ignored (only watching one file, parent updates are irrelevant)')
                return
            # When watching a single file, the only relevant event is the file being moved to/away, which counts as creation/deletion
            if self.source_file and self.target_file: # testing both even though we know they're both (un)set to make type checker happy
                self.debug(f"Event is move from/to outside of sync scope, treating as creation/deletion")
                if self.source_file == source_path:
                    os.unlink(self.target_file)
                    self.debug(f"Deleted file { self.target_file }")
                else:
                    # Create decrypted copy of file
                    with open(self.source_file) as src:
                        content: str = src.read()
                    with open(self.target_file, 'w') as tgt:
                        try:
                            tgt.write(Vault(content, keyring=self.keyring).as_plain())
                            self.debug(f"Created/Updated file { self.target_file } from vault contents")
                        except:
                            tgt.write(content)
                            self.debug(f"Created/Updated file { self.target_file } from plain contents")
            # Move file or directory
            else:
                move(target_path, new_target_path)
                self.debug(f"Moved { target_path } to { new_target_path }")
        except Exception as e:
            self.error('move', e)

    def on_modified(self, event: DirModifiedEvent | FileModifiedEvent) -> None:
        '''
        Filesystem hook for a modified source path.
        For files, the modified source content is copied to the corresponding target file, in decrypted form if it is a vault-like file.
        Directory modification events are ignored, as those are usually reundantly emitted for the parent directory of the actual filesystem event.
        '''
        self.debug(f"Captured event: { event }")
        try:
            source_path: str = event.src_path.decode('utf-8') if type(event.src_path) is bytes else event.src_path # type: ignore
            target_path: str = os.path.join(self.target_dir, os.path.relpath(source_path, self.source_dir))
            # Ignore parent modifications if we're watching a single file
            if self.source_file and source_path != self.source_file:
                self.debug('Event ignored (only watching one file, parent updates are irrelevant)')
                return
            # Ignore modified directories (seems to mean that a file in the directory was modified, we get an individual event for that)
            if type(event) is DirModifiedEvent:
                self.debug('Event ignored (already processed related event)')
                return
            # Create decrypted copy of file
            with open(source_path) as src:
                content: str = src.read()
            with open(target_path, 'w') as tgt:
                try:
                    tgt.write(Vault(content, keyring=self.keyring).as_plain())
                    self.debug(f"Created/Updated file { target_path } from vault contents")
                except:
                    tgt.write(content)
                    self.debug(f"Created/Updated file { target_path } from plain contents")
        except Exception as e:
            self.error('modify', e)

    def __repr__(self) -> str:
        src: str = self.source_file if self.source_file else self.source_dir
        tgt: str = self.target_file if self.target_file else self.target_dir
        return f"VaultDaemon({ src } -> { tgt })"
