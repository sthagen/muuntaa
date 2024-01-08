import logging
import pathlib
from unittest.mock import call

import muuntaa.writer as writer


def test_write_csaf_default(mocker):
    file_path = 'not-here.json'
    path = pathlib.Path(file_path).expanduser().resolve()
    options = {'ensure_ascii': False, 'indent': 2}
    mock_file = mocker.mock_open()
    mocker.patch('builtins.open', mock_file)
    payload = {'csaf': 42}
    expected_message = (logging.INFO, f'Successfully wrote {path}.')
    scoped_messages = writer.write_csaf(payload, file_path)

    mock_file.assert_called_once_with(path, 'wt', encoding=writer.ENCODING)
    mock_file().write.assert_has_calls(
        [call('{'), call(f'\n{" " * options["indent"]}'), call('"csaf"'), call(': '), call('42'), call('\n'), call('}')]
    )
    assert scoped_messages == [expected_message]


def test_write_csaf_compact(mocker):
    file_path = 'not-here.json'
    path = pathlib.Path(file_path).expanduser().resolve()
    options = {'ensure_ascii': False, 'indent': 0}
    mock_file = mocker.mock_open()
    mocker.patch('builtins.open', mock_file)
    payload = {'csaf': 42}
    expected_message = (logging.INFO, f'Successfully wrote {path}.')
    scoped_messages = writer.write_csaf(payload, file_path, options)

    mock_file.assert_called_once_with(path, 'wt', encoding=writer.ENCODING)
    mock_file().write.assert_has_calls(
        [call('{'), call('\n'), call('"csaf"'), call(': '), call('42'), call('\n'), call('}')]
    )
    assert scoped_messages == [expected_message]


def test_write_csaf_bad_suffix(mocker):
    file_path = 'bad-suffix.nosj'
    path = pathlib.Path(file_path).expanduser().resolve()
    options = {'ensure_ascii': False, 'indent': 0}
    mock_file = mocker.mock_open()
    mocker.patch('builtins.open', mock_file)
    payload = {'csaf': 42}
    expected_messages = [
        (logging.WARNING, f'Given output file {path} does not contain valid {writer.CSAF_FILE_SUFFIX} suffix.'),
        (logging.INFO, f'Successfully wrote {path}.'),
    ]
    scoped_messages = writer.write_csaf(payload, file_path, options)

    mock_file.assert_called_once_with(path, 'wt', encoding=writer.ENCODING)
    mock_file().write.assert_has_calls(
        [call('{'), call('\n'), call('"csaf"'), call(': '), call('42'), call('\n'), call('}')]
    )
    assert scoped_messages == expected_messages


def test_write_csaf_real_folder_no_file():
    file_path = 'test'
    path = pathlib.Path(file_path).expanduser().resolve()
    options = {'ensure_ascii': False, 'indent': 0}
    payload = {'csaf': 42}
    expected_message = (logging.CRITICAL, f'Writing output file {path} failed. list index out of range')
    scoped_messages = writer.write_csaf(payload, file_path, options)

    assert scoped_messages == [expected_message]


def test_write_csaf_create_folder(tmp_path):
    base_dir = tmp_path / 'missing-folder'
    path = base_dir / 'ok.json'
    file_path = str(path)
    payload = {'csaf': 42}
    expected_message = (logging.INFO, f'Created output folder {base_dir}.')
    scoped_messages = writer.write_csaf(payload, file_path)

    assert expected_message in scoped_messages


def test_write_csaf_overwrite_file(tmp_path):
    base_dir = tmp_path / 'folder'
    base_dir.mkdir()
    path = base_dir / 'ok.json'
    file_path = str(path)
    payload = {'csaf': 42}
    expected_message = (logging.INFO, f'Successfully wrote {path}.')
    scoped_messages = writer.write_csaf(payload, file_path)
    assert scoped_messages == [expected_message]

    # overwrite file
    expected_messages = [
        (logging.WARNING, f'Output {path} already exists. Overwriting it.'),
        expected_message,
    ]
    scoped_messages = writer.write_csaf(payload, file_path)
    assert scoped_messages == expected_messages
