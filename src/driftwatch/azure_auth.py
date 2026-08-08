"""Optional Azure token providers; importing driftwatch never requires azure-identity."""

from collections.abc import Sequence
from typing import Any

SQL_COPT_SS_ACCESS_TOKEN = 1256


def default_credential() -> Any:
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        raise RuntimeError("install driftwatch[azure] to use Azure credentials") from exc
    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def access_token(scope: str = "https://database.windows.net//.default", credential: Any = None) -> str:
    provider = credential or default_credential()
    token = provider.get_token(scope)
    return token.token


def odbc_access_token_attributes(
    token: str,
) -> dict[int, int | bytes | bytearray | str | Sequence[str]]:
    """Encode an Azure bearer token for Microsoft's SQL Server ODBC driver."""
    encoded = b"".join(bytes((byte, 0)) for byte in token.encode("utf-8"))
    return {SQL_COPT_SS_ACCESS_TOKEN: encoded}
