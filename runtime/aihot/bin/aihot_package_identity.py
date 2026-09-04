#!/usr/bin/env python3
"""Canonical legacy, daily, and bounded operator retry identities."""

from __future__ import annotations

import datetime as dt
import re


PACKAGE_RE = re.compile(
    r"^(?P<edition>20\d{2}-W(?:0[1-9]|[1-4]\d|5[0-3]))"
    r"(?:--(?P<attempt>20\d{2}-\d{2}-\d{2})(?:--r(?P<revision>[12]))?)?$"
)


def parse_package_id(value: str) -> tuple[str, str | None, int | None]:
    if not isinstance(value, str):
        raise ValueError("invalid package id")
    match = PACKAGE_RE.fullmatch(value)
    if match is None:
        raise ValueError("invalid package id")
    edition = match.group("edition")
    attempt = match.group("attempt")
    revision = (
        int(match.group("revision"))
        if match.group("revision")
        else (0 if attempt else None)
    )
    try:
        year, week = int(edition[:4]), int(edition[-2:])
        dt.date.fromisocalendar(year, week, 1)
        if attempt is not None:
            attempt_date = dt.date.fromisoformat(attempt)
            iso = attempt_date.isocalendar()
            if (iso.year, iso.week) != (year, week):
                raise ValueError("attempt date is outside edition")
    except ValueError as exc:
        if str(exc) == "attempt date is outside edition":
            raise
        raise ValueError("invalid package id") from exc
    return edition, attempt, revision
