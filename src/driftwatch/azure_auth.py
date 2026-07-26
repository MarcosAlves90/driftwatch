"""Optional Azure token providers; importing driftwatch never requires azure-identity."""

from typing import Any


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
