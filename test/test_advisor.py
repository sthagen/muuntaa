import pytest

import muuntaa.advisor as advisor


@pytest.mark.parametrize(
    'identifier,is_valid,expected',
    [
        ('42', True, f'42{advisor.CSAF_FILE_SUFFIX}'),
        ('a b', True, f'a_b{advisor.CSAF_FILE_SUFFIX}'),
        ('42', False, f'42{advisor.INVALID}{advisor.CSAF_FILE_SUFFIX}'),
        ('csaf', True, f'csaf{advisor.CSAF_FILE_SUFFIX}'),
        ('csaf', False, f'csaf{advisor.INVALID}{advisor.CSAF_FILE_SUFFIX}'),
        (None, True, f'{advisor.ID_UNKNOWN}{advisor.CSAF_FILE_SUFFIX}'),
    ]
)
def test_derive_csaf_filename(identifier, is_valid, expected):
    assert advisor.derive_csaf_filename(identifier, is_valid) == expected
