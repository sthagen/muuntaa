import datetime as dti
import logging

import pytest

import muuntaa.strftime as strftime


@pytest.mark.parametrize(
    'ts_text,expected',
    [
        ('4200-12-31T12:34:56Z', ('4200-12-31T12:34:56.000+00:00', [])),
        (
            'no-timestamp',
            (
                None,
                [
                    (
                        logging.CRITICAL,
                        "invalid time stamp provided no-timestamp: Invalid isoformat string: 'no-timestamp'.",
                    ),
                ],
            ),
        ),
    ],
)
def test_get_utc_timestamp(ts_text, expected):
    assert strftime.get_utc_timestamp(ts_text) == expected


def test_get_utc_now():
    earlier = dti.datetime.now(dti.timezone.utc).isoformat(timespec='milliseconds')
    ts_text, error = strftime.get_utc_timestamp(strftime.NOW_CODE)
    later = dti.datetime.now(dti.timezone.utc).isoformat(timespec='milliseconds')
    assert not error
    assert earlier <= ts_text <= later
