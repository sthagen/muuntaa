import re
from typing import Union

UNDERSCORE = '_'
ID_UNKNOWN = 'out'
INVALID = '_invalid'
CSAF_FILENAME_PATTERN = re.compile(r'([^+\-a-z0-9]+)')
CSAF_FILE_SUFFIX = '.json'


def derive_csaf_filename(identifier: Union[str, None] = None, is_valid: bool = False) -> str:
    """Returns CSAF filename derived from the identifier (according to CSAF v2.0 OASIS standard) and the validity.

    Cf. https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#51-filename

    If the advisory is not valid, then the stem of the derived filename ends in `_invalid`.
    """
    derived = CSAF_FILENAME_PATTERN.sub(UNDERSCORE, identifier.lower()) if identifier is not None else ID_UNKNOWN
    return f'{derived}{INVALID}{CSAF_FILE_SUFFIX}' if not is_valid else f'{derived}{CSAF_FILE_SUFFIX}'
