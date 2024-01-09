import logging

import muuntaa.cli as cli
from muuntaa import APP_NAME, VERSION


def test_app_version(capsys):
    code = cli.app(['--version'])
    assert code == 0
    out, err = capsys.readouterr()
    assert not err
    assert VERSION in out


def test_app_help(capsys):
    code = cli.app(['--help'])
    assert code == 0
    out, err = capsys.readouterr()
    assert not err
    assert APP_NAME in out


def test_app_invalid_input_file_content(caplog, capsys):
    caplog.set_level(logging.INFO)
    code = cli.app(['--input-file', 'README.md'])
    assert code == 0  # TODO(sthagen): for now OK, real implementation SHALL return 1
    out, err = capsys.readouterr()
    assert not err
    assert not out
    assert 'out_invalid.json.' in caplog.text


def test_app_input_file_path_missing(caplog, capsys):
    caplog.set_level(logging.INFO)
    code = cli.app(['--input-file', 'not-present.xml'])
    assert code == 0  # TODO(sthagen): for now OK, real implementation SHALL return 1
    out, err = capsys.readouterr()
    assert not err
    assert not out
    assert 'Input file not found, check the path: not-present.xml' in caplog.text


def test_app_invalid_input_file_content_override_force(caplog, capsys):
    caplog.set_level(logging.INFO)
    code = cli.app(['--input-file', 'README.md', '--force'])
    assert code == 0  # TODO(sthagen): for now OK, real implementation SHALL return 1
    out, err = capsys.readouterr()
    assert not err
    assert not out
    assert 'out_invalid.json.' in caplog.text


