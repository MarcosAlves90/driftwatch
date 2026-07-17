import re


def normalize_sql(value: str | None) -> str | None:
    if value is None:
        return None
    value = re.sub(r"/\*.*?\*/", " ", value, flags=re.S)
    value = re.sub(r"--[^\r\n]*", " ", value)
    return " ".join(value.split()).lower()
