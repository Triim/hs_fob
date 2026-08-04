"""JSON Canonicalization Scheme (RFC 8785) — the bytes a credential is signed over.

A Data Integrity proof signs a *document*, not a particular serialization of it.
Two verifiers that re-serialize the same credential differently would compute
different signing bytes and disagree about a perfectly valid signature, so the
document is first reduced to one canonical byte string. This module implements
the subset of RFC 8785 the credential shapes here actually use:

- **objects**: keys sorted by their UTF-16 code units (RFC 8785 §3.2.3), emitted
  ``{"k":v,...}`` with no whitespace;
- **arrays**: order preserved, no whitespace;
- **strings**: JSON escaping with the shortest form, non-ASCII emitted literally
  as UTF-8 (``ensure_ascii=False``);
- **integers / booleans / null**: their obvious JSON forms.

**Floats are rejected**, deliberately. RFC 8785 mandates ECMAScript
``Number::toString`` formatting for them, which Python's ``repr`` matches only
by coincidence over part of the range; rather than ship a subtly wrong number
serializer, a credential simply may not contain a float. Every field we sign is
a string, list, object or integer, so the restriction costs nothing and removes
a whole class of cross-implementation signature mismatches.

This is JCS, **not** RDF canonicalization: the credential is treated as plain
JSON, which is what the ``eddsa-jcs-2022`` cryptosuite specifies (and what keeps
a browser holder able to reason about the same bytes without a JSON-LD toolkit).
"""

from __future__ import annotations

import json


def _sort_key(key: str) -> tuple[int, ...]:
    """UTF-16 code-unit ordering of ``key``, as RFC 8785 §3.2.3 requires.

    Python's ``sorted`` on ``str`` orders by Unicode *code point*, which differs
    from UTF-16 code-unit order for characters outside the Basic Multilingual
    Plane (they sort as surrogate pairs, i.e. below U+E000). Encoding to UTF-16
    big-endian and comparing the resulting 16-bit units reproduces the required
    order exactly.
    """
    raw = key.encode("utf-16-be")
    return tuple(int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2))


def canonicalize(value) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of ``value``.

    Args:
        value: A JSON-compatible structure of ``dict`` / ``list`` / ``str`` /
            ``int`` / ``bool`` / ``None``.

    Raises:
        TypeError: If ``value`` contains a float (see the module docstring) or
            any other type with no defined canonical form, or an object key that
            is not a string.
    """
    return _canonicalize(value).encode("utf-8")


def _canonicalize(value) -> str:
    # bool before int: bool is a subclass of int, and True must serialize as
    # "true", not "1".
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise TypeError(
            "floats have no canonical form here — see credentials.jcs; "
            "use an integer or a string"
        )
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"object keys must be strings, got {type(key)!r}")
        items = sorted(value.items(), key=lambda kv: _sort_key(kv[0]))
        return (
            "{"
            + ",".join(
                f"{json.dumps(k, ensure_ascii=False)}:{_canonicalize(v)}"
                for k, v in items
            )
            + "}"
        )
    raise TypeError(f"no canonical JSON form for {type(value)!r}")
