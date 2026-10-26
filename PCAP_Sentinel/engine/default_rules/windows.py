"""Provided helpers: time windows over timestamp-ordered items (used by most rules)."""
from __future__ import annotations

from typing import Callable, Hashable, Iterable, List, Sequence


def sorted_by_time(packets: Iterable[dict]) -> List[dict]:
    """Packets that have a timestamp, ordered by capture time (stable for equal times)."""
    return sorted((p for p in packets if p.get("timestamp") is not None),
                  key=lambda p: (p["timestamp"], p["packet_number"]))


def episodes_by_count(items: Sequence, time_of: Callable, window: float, threshold: int,
                      max_episodes: int = 5) -> List[list]:
    """Non-overlapping episodes in which >= ``threshold`` items fall inside any ``window`` seconds.

    ``items`` must be sorted by ``time_of``. An episode grows for as long as the sliding window
    keeps meeting the threshold, so one long flood is reported once, not hundreds of times.
    """
    out: List[list] = []
    left, start, end = 0, None, None
    for right in range(len(items)):
        while time_of(items[right]) - time_of(items[left]) > window:
            left += 1
        if right - left + 1 >= threshold:
            if start is None:
                start = left
            end = right
        elif start is not None:
            out.append(list(items[start:end + 1]))
            start = end = None
            left = right
            if len(out) >= max_episodes:
                return out
    if start is not None and len(out) < max_episodes:
        out.append(list(items[start:end + 1]))
    return out


def episodes_by_distinct(items: Sequence, time_of: Callable, key_of: Callable[..., Hashable],
                         window: float, threshold: int, max_episodes: int = 5) -> List[list]:
    """Like ``episodes_by_count`` but counts DISTINCT ``key_of(item)`` values in the window."""
    out: List[list] = []
    counts: dict = {}
    left, start, end = 0, None, None
    for right in range(len(items)):
        key = key_of(items[right])
        counts[key] = counts.get(key, 0) + 1
        while time_of(items[right]) - time_of(items[left]) > window:
            old = key_of(items[left])
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
            left += 1
        if len(counts) >= threshold:
            if start is None:
                start = left
            end = right
        elif start is not None:
            out.append(list(items[start:end + 1]))
            start = end = None
            counts = {key_of(items[right]): 1}
            left = right
            if len(out) >= max_episodes:
                return out
    if start is not None and len(out) < max_episodes:
        out.append(list(items[start:end + 1]))
    return out


def group_by(items: Iterable, key_of: Callable) -> dict:
    groups: dict = {}
    for item in items:
        key = key_of(item)
        if key is not None:
            groups.setdefault(key, []).append(item)
    return groups
