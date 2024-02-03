"""Handling functions for configuration resources."""

import logging
import pkgutil
from typing import Iterable, Union

import yaml

from muuntaa import BOOLEAN_KEYS, ConfigType, ENCODING, Pathlike, ScopedMessages

CONFIG_RESOURCE = 'resource/config.yml'


def boolify(configuration: ConfigType, boolean_keys: Union[Iterable[str], None] = None) -> ScopedMessages:
    """Modify configuration in place to ensure the values of boolean keys are converted to booleans."""
    scoped_messages: ScopedMessages = []
    if boolean_keys is None:
        boolean_keys = BOOLEAN_KEYS
    for key in boolean_keys:
        try:
            incoming = configuration[key]
        except KeyError as err:
            scoped_messages.append(
                (logging.CRITICAL, f'Parsing configuration failed. Missing config key {key}: {err}.'),
            )
            continue

        try:
            if isinstance(incoming, bool):
                configuration[key] = incoming
                continue
            if isinstance(incoming, str):
                canonical = incoming.strip().lower()
                if canonical in {'true', 'yes', '1', 'y'}:
                    configuration[key] = True
                    continue
                if canonical in {'false', 'no', '0', 'n'}:
                    configuration[key] = False
                    continue
            raise ValueError('unexpected value')
        except (AttributeError, ValueError) as err:
            scoped_messages.append(
                (
                    logging.CRITICAL,
                    f'Parsing configuration failed. Invalid value for config key {key}: {incoming} {err}.',
                ),
            )

    return scoped_messages


def load(external_path: Union[None, Pathlike] = None) -> ConfigType:
    """Load the configuration either from the package resources (default) or an external path."""
    if external_path:
        with open(external_path, 'rt', encoding=ENCODING) as handle:
            return yaml.safe_load(handle)  # type: ignore
    else:
        return yaml.safe_load(pkgutil.get_data(__package__, CONFIG_RESOURCE).decode(encoding=ENCODING))  # type: ignore


def eject() -> str:
    """Dump the configuration from the package resources to a YAML string."""
    return pkgutil.get_data(__package__, CONFIG_RESOURCE).decode(encoding=ENCODING)  # type: ignore
