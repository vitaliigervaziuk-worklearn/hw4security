def fenced(label: str, text: str) -> str:
    """
    Wrap untrusted text in a strong delimiter.
    Helps reduce instruction confusion (defense-in-depth).
    """
    return f"<{label}>\n{text}\n</{label}>"
