import logging
import pathlib

import yaml

import muuntaa.config as cfg


def test_load():
    configuration = cfg.load()
    assert configuration['csaf_version'] == '2.0'


def test_load_external():
    configuration = cfg.load(pathlib.Path('muuntaa') / 'resource' / 'config.yml')
    assert configuration['csaf_version'] == '2.0'


def test_eject():
    ejected = cfg.eject()
    assert ejected
    configuration = yaml.safe_load(ejected)
    assert configuration['csaf_version'] == '2.0'


def test_boolify_truthy():
    configuration = cfg.load()
    key = 'force'
    assert configuration[key] is False
    for override in (True, 'true', 'yes', '1', 'y'):
        configuration[key] = override
        scoped_messages = cfg.boolify(configuration)
        assert configuration[key] is True
        assert not scoped_messages


def test_boolify_falsy():
    configuration = cfg.load()
    key = 'force'
    assert configuration[key] is False
    for override in (False, 'false', 'no', '0', 'n'):
        configuration[key] = override
        scoped_messages = cfg.boolify(configuration)
        assert configuration[key] is False
        assert not scoped_messages


def test_boolify_inconvertible():
    configuration = cfg.load()
    key = 'force'
    assert configuration[key] is False
    inconvertible = 'we-are-picky'
    configuration[key] = inconvertible
    expected_scoped_message = (
        logging.CRITICAL,
        f'Parsing configuration failed. Invalid value for config key {key}: {inconvertible} unexpected value.',
    )
    scoped_messages = cfg.boolify(configuration)
    assert configuration[key] == 'we-are-picky'
    assert scoped_messages == [expected_scoped_message]


def test_boolify_missing_key():
    configuration = cfg.load()
    key = 'force'
    assert configuration[key] is False
    del configuration[key]
    expected_scoped_message = (logging.CRITICAL, f"Parsing configuration failed. Missing config key {key}: '{key}'.")
    scoped_messages = cfg.boolify(configuration)
    assert key not in configuration
    assert scoped_messages == [expected_scoped_message]


def test_boolify_explicit_boolean_keys():
    configuration = cfg.load()
    key = 'force'
    assert configuration[key] is False
    other_key = 'remove_CVSS_values_without_vector'
    assert configuration[other_key] is False
    configuration[other_key] = 'yes'
    immutable = 'we-stay-as-we-are'
    configuration[key] = immutable
    scoped_messages = cfg.boolify(configuration, boolean_keys=('remove_CVSS_values_without_vector',))
    assert configuration[key] == immutable
    assert configuration[other_key] is True
    assert not scoped_messages
