from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizationOptions:
    ignore_whitespace: bool = True
    ignore_comments: bool = True
    normalize_keywords_case: bool = True


def normalize_sql(value: str | None, options: NormalizationOptions | None = None) -> str | None:
    """Safely normalize SQL while preserving quoted literals."""
    if value is None:
        return None
    options = options or NormalizationOptions()
    output: list[str] = []
    normal_buffer: list[str] = []
    index = 0

    def flush_normal() -> None:
        if normal_buffer:
            text = " ".join("".join(normal_buffer).split()) if options.ignore_whitespace else "".join(normal_buffer)
            output.append(text.lower() if options.normalize_keywords_case else text)
            normal_buffer.clear()

    while index < len(value):
        character = value[index]
        next_character = value[index + 1] if index + 1 < len(value) else ""
        if options.ignore_comments and character == "-" and next_character == "-":
            flush_normal()
            index += 2
            while index < len(value) and value[index] not in "\r\n":
                index += 1
            continue
        if options.ignore_comments and character == "/" and next_character == "*":
            flush_normal()
            index += 2
            while index + 1 < len(value) and value[index : index + 2] != "*/":
                index += 1
            index = min(len(value), index + 2)
            continue
        if character in "'\"":
            flush_normal()
            quote = character
            literal = [character]
            index += 1
            while index < len(value):
                literal.append(value[index])
                if value[index] == quote:
                    if index + 1 < len(value) and value[index + 1] == quote:
                        index += 1
                        literal.append(value[index])
                    else:
                        index += 1
                        break
                index += 1
            output.append("".join(literal))
            continue
        normal_buffer.append(character)
        index += 1
    flush_normal()
    return " ".join(part for part in output if part) if options.ignore_whitespace else "".join(output)
