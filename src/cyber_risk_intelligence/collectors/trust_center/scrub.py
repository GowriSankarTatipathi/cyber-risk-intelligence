"""Remove page code that trips the secret check without touching what the page says.

Public web pages often embed browser keys and tokens in their code: a maps or
search key in a ``<script>``, a widget's ``api-key="..."`` attribute, a signed
token in a ``data-*`` attribute. These keys are published to every visitor on
purpose, but they look like credentials, and we never store anything that does.

When a page trips the secret check, ``scrub_html`` drops scripts, styles,
``<noscript>``/``<template>`` blocks and HTML comments, and removes any attribute
whose value still looks like a secret. The visible text, headings and the
``<meta>``/``<title>`` tags we read dates and titles from are kept. If the
scrubbed page still trips the check (a password written in the page text, for
example), it is withheld as before.
"""

from __future__ import annotations

from bs4 import BeautifulSoup, Comment

from ...evidence import find_secrets

_CODE_TAGS = ("script", "style", "noscript", "template")


def scrub_html(content: bytes) -> tuple[bytes, int]:
    """The page with code and secret-like attribute values removed, and how many items were removed."""
    soup = BeautifulSoup(content, "html.parser")
    removed = 0
    for tag in soup(_CODE_TAGS):
        tag.decompose()
        removed += 1
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()
        removed += 1
    for tag in soup.find_all(True):
        for name, value in list(tag.attrs.items()):
            text = " ".join(value) if isinstance(value, list) else str(value)
            if find_secrets(f'{name}="{text}"'.encode()):
                del tag.attrs[name]
                removed += 1
    return str(soup).encode("utf-8"), removed
