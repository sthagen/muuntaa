import json
import logging
import pathlib
from typing import Union

Pathlike = Union[str, pathlib.Path]
LogLevel = int
ScopedMessage = tuple[LogLevel, str]
WriterOptions = Union[None, dict[str, Union[bool, int]]]

CSAF_FILE_SUFFIX = '.json'
ENCODING = 'utf-8'


def write_csaf(csaf_dict: dict[str, object], file_path: Pathlike, options: WriterOptions = None) -> list[ScopedMessage]:
    """Write the CSAF data from python dict into a CSAF JSON file creating path as needed."""
    if options is None:
        options = {'ensure_ascii': False, 'indent': 2}
    scoped_messages = []
    path = pathlib.Path(file_path).expanduser().resolve()
    base_dir = path.parent.absolute()
    try:
        if not base_dir.is_dir():
            path.mkdir(parents=True, exist_ok=True)
            scoped_messages.append((logging.INFO, f'Created output folder {base_dir}.'))
        if path.is_file():
            scoped_messages.append((logging.WARNING, f'Output {path} already exists. Overwriting it.'))
        if path.suffixes[-1] != CSAF_FILE_SUFFIX:
            scoped_messages.append(
                (logging.WARNING, f'Given output file {path} does not contain valid {CSAF_FILE_SUFFIX} suffix.')
            )
        with open(path, 'wt', encoding=ENCODING) as handle:
            json.dump(csaf_dict, handle, **options)  # type: ignore
            scoped_messages.append((logging.INFO, f'Successfully wrote {path}.'))

    except Exception as err:  # noqa
        scoped_messages.append((logging.CRITICAL, f'Writing output file {path} failed. {err}'))

    return scoped_messages
