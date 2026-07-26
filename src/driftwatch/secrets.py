import re

from .models import Credentials

_SECRET_KEYS = {
    "pwd": "password",
    "password": "password",
    "clientsecret": "client_secret",
    "client_secret": "client_secret",
    "client secret": "client_secret",
    "accesstoken": "access_token",
    "access_token": "access_token",
    "access token": "access_token",
    "token": "token",
}
_USERNAME_KEYS = {"uid", "user id", "userid", "username", "user"}


def _split_segments(value: str) -> list[str]:
    segments: list[str] = []
    start = 0
    brace_depth = 0
    index = 0
    while index < len(value):
        character = value[index]
        if character == "{" and brace_depth == 0:
            brace_depth = 1
        elif character == "}" and brace_depth:
            if index + 1 < len(value) and value[index + 1] == "}":
                index += 1
            else:
                brace_depth = 0
        elif character == ";" and brace_depth == 0:
            segments.append(value[start:index])
            start = index + 1
        index += 1
    segments.append(value[start:])
    return segments


def _unbrace(value: str) -> str:
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        return value[1:-1].replace("}}", "}")
    return value


def split_connection_string(value: str) -> tuple[str, Credentials]:
    safe_segments: list[str] = []
    values: dict[str, str] = {}
    for segment in _split_segments(value):
        if "=" not in segment:
            if segment.strip():
                safe_segments.append(segment)
            continue
        key, raw_value = segment.split("=", 1)
        normalized_key = key.strip().casefold()
        if normalized_key in _SECRET_KEYS or normalized_key in _USERNAME_KEYS:
            values[normalized_key] = _unbrace(raw_value)
        else:
            safe_segments.append(segment)
    credentials = Credentials(
        username=next((values[key] for key in _USERNAME_KEYS if key in values), None),
        password=next((values[key] for key in ("pwd", "password") if key in values), None),
        client_secret=next(
            (values[key] for key in ("clientsecret", "client_secret", "client secret") if key in values),
            None,
        ),
        access_token=next(
            (values[key] for key in ("accesstoken", "access_token", "access token") if key in values),
            None,
        ),
        token=values.get("token"),
    )
    return ";".join(safe_segments), credentials


def _odbc_value(value: str) -> str:
    if not any(character in value for character in ";{}"):
        return value
    return "{" + value.replace("}", "}}") + "}"


def append_credentials(base: str, credentials: Credentials) -> str:
    values = []
    if credentials.username is not None:
        values.append(("UID", credentials.username))
    if credentials.password is not None:
        values.append(("PWD", credentials.password))
    if credentials.client_secret is not None:
        values.append(("ClientSecret", credentials.client_secret))
    if credentials.access_token is not None:
        values.append(("AccessToken", credentials.access_token))
    if credentials.token is not None:
        values.append(("Token", credentials.token))
    suffix = "".join(f";{key}={_odbc_value(value)}" for key, value in values)
    return base + suffix


def redact_secrets(message: str) -> str:
    pattern = (
        r"(?i)\b(pwd|password|client[ _-]?secret|access[ _-]?token|token)"
        r"\s*=\s*(\{(?:[^}]|}})*\}|[^;\s]*)"
    )
    return re.sub(pattern, r"\1=[REDACTED]", message)
