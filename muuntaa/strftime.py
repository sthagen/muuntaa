import datetime as dti
import logging
from typing import Union

from muuntaa import NOW_CODE, ScopedMessages


def _line_slug(text: str) -> str:
    """Remove all new lines from text."""
    return text.replace('\n', ' ').replace('\r', ' ')


def get_utc_timestamp(ts_text: str = NOW_CODE) -> tuple[Union[str, None], ScopedMessages]:
    """Returns an ordered pair of timestamp in UTC format and error (empty scoped messages no error).

    If the magic timestamp text `now` is provided, then the current timestamp is returned.
    """
    if ts_text == NOW_CODE:
        return dti.datetime.now(dti.timezone.utc).isoformat(timespec='milliseconds'), []
    try:
        now = dti.datetime.fromisoformat(ts_text.replace('Z', '+00:00'))
        if now.tzinfo is None:
            now = now.replace(tzinfo=dti.timezone.utc)
        return now.isoformat(timespec='milliseconds'), []
    except (TypeError, ValueError) as err:
        return None, [(logging.CRITICAL, f'invalid time stamp provided {ts_text}: {_line_slug(str(err))}.')]
