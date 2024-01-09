import argparse
import logging
import pathlib
import sys
from typing import Union

import muuntaa.advisor as advisor
import muuntaa.config as cfg
import muuntaa.writer as writer
from muuntaa import (
    APP_ALIAS,
    APP_NAME,
    ConfigType,
    ENCODING,
    INPUT_FILE_KEY,
    OVERWRITABLE_KEYS,
    ScopedMessages,
    VERSION,
    log,
)

FALLBACK_CVSS3_VERSION = '3.0'
MAGIC_CMD_ARG_ENTERED = 'cmd-arg-entered'

scoped_log = log.log  # noqa


def parse_request(argv: Union[list[str], None] = None) -> tuple[Union[int, ConfigType], ScopedMessages]:
    """Parse the request as load configuration and mix in (overwrite) command line parameter values."""
    if argv is None:
        argv = sys.argv[1:]  # pragma: no cover
    parser = argparse.ArgumentParser(
        prog=APP_ALIAS, description=APP_NAME, formatter_class=argparse.RawTextHelpFormatter
    )
    # General args
    parser.add_argument('-v', '--version', action='version', version=VERSION)
    parser.add_argument(
        '--input-file', dest='input_file', type=str, required=True, help='CVRF XML input file to parse', metavar='PATH'
    )
    parser.add_argument(
        '--output-dir',
        dest='output_dir',
        type=str,
        default='./',
        metavar='PATH',
        help='CSAF output dir to write to. Filename is derived from /document/tracking/id.',
    )
    parser.add_argument(
        '--print',
        dest='print',
        action='store_true',
        default=False,
        help='Additionally prints CSAF JSON output on stdout.',
    )
    parser.add_argument(
        '--force',
        action='store_const',
        const='cmd-arg-entered',
        help=(
            'If used, the converter produces output even if it is invalid (errors occurred during conversion).\n'
            'Target use case: best-effort conversion to JSON, fix the errors manually, e.g. in Secvisogram.'
        ),
    )

    # Document Publisher args
    parser.add_argument('--publisher-name', dest='publisher_name', type=str, help='Name of the publisher.')
    parser.add_argument(
        '--publisher-namespace',
        dest='publisher_namespace',
        type=str,
        help='Namespace of the publisher. Must be a valid URI',
    )

    # Document Tracking args
    parser.add_argument(
        '--fix-insert-current-version-into-revision-history',
        action='store_const',
        const='cmd-arg-entered',
        help=(
            'If the current version is not present in the revision history the current version is\n'
            'added to the revision history. Also, warning is produced. By default, an error is produced.'
        ),
    )

    # Document References args
    parser.add_argument(
        '--force-insert-default-reference-category',
        action='store_const',
        const='cmd-arg-entered',
        help="When 'Type' attribute not present in 'Reference' element, then force using default value 'external'.",
    )

    # Vulnerabilities args
    parser.add_argument(
        '--remove-CVSS-values-without-vector',
        action='store_const',
        const='cmd-arg-entered',
        help=(
            'If vector is not present in CVSS ScoreSet,\n'
            'the convertor removes the whole ScoreSet instead of producing an error.'
        ),
    )

    parser.add_argument(
        '--default-CVSS3-version',
        dest='default_CVSS3_version',
        help=(
            'Default version used for CVSS version 3, when the version cannot be derived from other sources.\n'
            f"Default value is '{FALLBACK_CVSS3_VERSION}'."
        ),
    )

    try:
        args = {k: v for k, v in vars(parser.parse_args(argv)).items() if v is not None}
    except SystemExit as err:
        return int(str(err)), []

    config = cfg.load()
    scoped_messages = cfg.boolify(config)
    for scope, message in scoped_messages:
        scoped_log(scope, message)
        if scope >= logging.CRITICAL:
            return 1, []

    config.update(args)  # Update and overwrite config file values with the ones from command line arguments
    for key in OVERWRITABLE_KEYS:  # Boolean optional arguments that are also present in config need special treatment
        if config.get(key) == MAGIC_CMD_ARG_ENTERED:
            config[key] = True

    if not pathlib.Path(config.get(INPUT_FILE_KEY, '')).is_file():  # type: ignore
        # Avoided type error using empty string as default, which fakes missing file per current dir
        scoped_log(logging.CRITICAL, f'Input file not found, check the path: {config.get(INPUT_FILE_KEY)}')
        return 1, []

    return config, []


def process(configuration: ConfigType) -> int:
    """Visit the source and yield the requested transformed target."""
    in_path = pathlib.Path(configuration[INPUT_FILE_KEY])  # type: ignore
    with open(in_path, 'r', encoding=ENCODING) as source:
        loaded = source.read()

    csaf_dict: dict[str, object] = {'csaf_version': '2.0', 'incoming_blob': loaded}

    out_path = advisor.derive_csaf_filename()
    scoped_messages = writer.write_csaf(csaf_dict, out_path)
    for scope, message in scoped_messages:
        scoped_log(scope, message)
        if scope >= logging.CRITICAL:
            return 1

    return 0


def app(argv: Union[list[str], None] = None) -> int:
    """Delegate processing to functional module."""
    argv = sys.argv[1:] if argv is None else argv
    configuration, scoped_messages = parse_request(argv)
    if isinstance(configuration, int):
        return 0
    return process(configuration)
