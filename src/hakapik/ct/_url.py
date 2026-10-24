"""URL helper shared by the CT log clients."""


def base_url(url: str) -> str:
    """Return url with exactly one trailing slash."""
    return url.rstrip("/") + "/"
