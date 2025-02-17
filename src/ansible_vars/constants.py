# Constant types and values for ansible-vars

# Standard library imports
from typing import Hashable, Any

# Sentinel classes

class Unset():
    '''A sentinel marking that an optional argument is not set, used where None is a valid argument value.'''
    pass

class ThrowError():
    '''A sentinel marking that an error should be thrown during the operation if a specified condition is met.'''
    pass

# Type hints

# Specify an octal by writing 0o<number>
octal = int

# YAML Types indexable by Hashables
Indexable = dict[Hashable, Any] | list[Any]

# Type of a list of changed paths
ChangeList = list[tuple[Hashable, ...]]

# ((start_line, start_col), (end_line, end_col)) of a query match on a string
MatchLocation = tuple[tuple[int, int], tuple[int, int]]

# Vault parser and edit mode config

# The YAML parser cannot handle empty data, so we insert a fake root key before parsing and remove it before exporting
SENTINEL_KEY: str = '__parser_root_do_not_remove__'

# YAML tag to be applied to variables which should be encrypted in edit mode
ENCRYPTED_VAR_TAG: str = u'!enc'

# Header inserted at the top of a file being edited
# Will be searched for and removed on re-parsing
EDIT_MODE_HEADER: str = f"""
#~ DO NOT EDIT THIS HEADER
#~ Variables which should be encrypted are formatted as '{ ENCRYPTED_VAR_TAG } <value>'.
#~ Do not remove this prefix unless you want to convert them to plain variables.
#~ Add the prefix to any string variable you want to be encrypted.

""".lstrip('\n')

# Diff log filenames

# Default filename for a plaintext vault log
DEFAULT_PLAIN_LOGNAME: str = 'vault_changelog_plain.log'
