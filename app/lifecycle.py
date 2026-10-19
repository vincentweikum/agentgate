"""API lifecycle controls: deprecation, sunset, and retirement.

Deprecated versions keep working but every response carries standard headers
telling callers it's going away and where to move:
  Deprecation: @<unix time>          (RFC 9745)
  Sunset: <HTTP date>                (RFC 8594)
  Link: <...>; rel="successor-version"
After the sunset date the version is retired and returns 410 Gone.
"""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from email.utils import format_datetime

from .config import load_catalog_entry
from .errors import APIError


def version_info(version: str) -> dict:
    for v in load_catalog_entry()["versions"]:
        if v["version"] == version:
            return v
    raise KeyError(version)


def _as_date(value) -> date:
    return value if isinstance(value, date) else date.fromisoformat(str(value))


def is_retired(version: str, today: date | None = None) -> bool:
    info = version_info(version)
    if info["status"] == "retired":
        return True
    sunset = info.get("sunset_on")
    return bool(sunset) and (today or date.today()) > _as_date(sunset)


def deprecation_headers(version: str, successor_path: str | None = None) -> dict[str, str]:
    info = version_info(version)
    if info["status"] != "deprecated":
        return {}
    headers = {}
    if info.get("deprecated_on"):
        dep = datetime.combine(_as_date(info["deprecated_on"]), time.min, tzinfo=timezone.utc)
        headers["Deprecation"] = f"@{int(dep.timestamp())}"
    if info.get("sunset_on"):
        sunset = datetime.combine(_as_date(info["sunset_on"]), time.min, tzinfo=timezone.utc)
        headers["Sunset"] = format_datetime(sunset, usegmt=True)
    if successor_path:
        headers["Link"] = f'<{successor_path}>; rel="successor-version"'
    return headers


def ensure_not_retired(version: str) -> None:
    if is_retired(version):
        successor = version_info(version).get("successor")
        raise APIError(410, "version_retired", "API version retired",
                       f"API {version} has been retired. Use {successor} instead.")
