import datetime as dti
from typing import Union

NOW_CODE = 'now'


def _line_slug(text: str) -> str:
    """Remove all new lines from text."""
    return text.replace('\n', ' ').replace('\r', ' ')


def get_utc_timestamp(ts_text: str = NOW_CODE) -> tuple[Union[str, None], str]:
    """Returns an ordered pair of timestamp in UTC format and error (empty string indicates no error).

    If the magic timestamp text `now` is provided, then the current timestamp is returned.
    """
    if ts_text == NOW_CODE:
        return dti.datetime.now(dti.timezone.utc).isoformat(timespec='milliseconds'), ''
    try:
        now = dti.datetime.fromisoformat(ts_text.replace('Z', '+00:00'))
        if now.tzinfo is None:
            now = now.replace(tzinfo=dti.timezone.utc)
        return now.isoformat(timespec='milliseconds'), ''
    except (TypeError, ValueError) as err:
        return None, f'invalid time stamp provided {ts_text}: {_line_slug(str(err))}.'
