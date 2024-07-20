"""Convert (Finnish: muuntaa) CVRF v1.2 XML to CSAF v2.0 JSON documents."""

import datetime as dti
import logging
import os
import pathlib
import sys
from typing import Union, no_type_check

# [[[fill git_describe()]]]
__version__ = '2024.1.9+parent.abadcafe'
# [[[end]]]
__version_info__ = tuple(
    e if '-' not in e else e.split('-')[0] for part in __version__.split('+') for e in part.split('.') if e != 'parent'
)

APP_ALIAS = str(pathlib.Path(__file__).parent.name)
APP_ENV = APP_ALIAS.upper()
APP_NAME = locals()['__doc__']
DEBUG = bool(os.getenv(f'{APP_ENV}_DEBUG', ''))
ENCODING = 'utf-8'
ENCODING_ERRORS_POLICY = 'ignore'
DEFAULT_CONFIG_NAME = f'.{APP_ALIAS}.yml'
log = logging.getLogger()  # Module level logger is sufficient
LOG_FOLDER = pathlib.Path('logs')
LOG_FILE = f'{APP_ALIAS}.log'
LOG_PATH = pathlib.Path(LOG_FOLDER, LOG_FILE) if LOG_FOLDER.is_dir() else pathlib.Path(LOG_FILE)
LOG_LEVEL = logging.INFO
VERSION = __version__
VERSION_DOTTED_TRIPLE = '.'.join(__version_info__[:3])
TS_FORMAT_LOG = '%Y-%m-%dT%H:%M:%S'
BOOLEAN_KEYS = ('force', 'fix_insert_current_version_into_revision_history')
INPUT_FILE_KEY = 'input_file'
NOW_CODE = 'now'
OVERWRITABLE_KEYS = [
    'fix_insert_current_version_into_revision_history',
    'force_insert_default_reference_category',
    'remove_CVSS_values_without_vector',
    'force',
]
CSAF_FILE_SUFFIX = '.json'

ConfigType = dict[str, Union[None, bool, int, float, str]]
LogLevel = int
Pathlike = Union[pathlib.Path, str]
ScopedMessage = tuple[LogLevel, str]
ScopedMessages = list[ScopedMessage]
WriterOptions = Union[None, dict[str, Union[bool, int]]]


def cleanse_id(id_string: str) -> str:
    """Strips spaces and linebreaks from the ID string and logs a warning if the ID string was changed."""
    if (cleansed := id_string.strip().replace('\r', '').replace('\n', '')) != id_string:
        logging.warning('The ID string contained leading/trailing whitespace or linebreaks. These were removed.')
    return cleansed


def integer_tuple(text: str) -> tuple[int, ...]:
    """Convert a string of dotted integers into tuple of integers"""
    try:
        return tuple(int(part) for part in text.split('.'))
    except ValueError:
        return (sys.maxsize,)


__all__: list[str] = [
    'APP_ALIAS',
    'APP_ENV',
    'APP_NAME',
    'BOOLEAN_KEYS',
    'CSAF_FILE_SUFFIX',
    'DEBUG',
    'DEFAULT_CONFIG_NAME',
    'ConfigType',
    'ENCODING',
    'ENCODING_ERRORS_POLICY',
    'INPUT_FILE_KEY',
    'LogLevel',
    'NOW_CODE',
    'OVERWRITABLE_KEYS',
    'Pathlike',
    'ScopedMessage',
    'ScopedMessages',
    'VERSION',
    'VERSION_DOTTED_TRIPLE',
    'WriterOptions',
    'cleanse_id',
    'integer_tuple',
    'log',
]


@no_type_check
def formatTime_RFC3339(self, record, datefmt=None):  # noqa
    """HACK A DID ACK we could inject .astimezone() to localize ..."""
    return dti.datetime.fromtimestamp(record.created, dti.timezone.utc).isoformat()  # pragma: no cover


@no_type_check
def init_logger(name=None, level=None):
    """Initialize module level logger"""
    global log  # pylint: disable=global-statement

    log_format = {
        'format': '%(asctime)s %(levelname)s [%(name)s]: %(message)s',
        'datefmt': TS_FORMAT_LOG,
        # 'filename': LOG_PATH,
        'level': LOG_LEVEL if level is None else level,
    }
    logging.Formatter.formatTime = formatTime_RFC3339
    logging.basicConfig(**log_format)
    log = logging.getLogger(APP_ENV if name is None else name)
    log.propagate = True


init_logger(name=APP_ENV, level=logging.DEBUG if DEBUG else None)
