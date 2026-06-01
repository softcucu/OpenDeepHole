"""Lightweight per-scan Server-Sent Events pub/sub using asyncio.Queue."""

from __future__ import annotations

import asyncio
import json
from typing import Any


# scan_id -> set of subscriber queues
_scan_subscribers: dict[str, set[asyncio.Queue[dict]]] = {}


def subscribe(scan_id: str) -> asyncio.Queue[dict]:
    """Create a new subscriber queue for the given scan.

    Returns an asyncio.Queue that will receive published events.
    The queue has a bounded size; slow consumers will have events dropped.
    """
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=50)
    _scan_subscribers.setdefault(scan_id, set()).add(queue)
    return queue


def unsubscribe(scan_id: str, queue: asyncio.Queue[dict]) -> None:
    """Remove a subscriber queue.  Cleans up empty scan entries."""
    subs = _scan_subscribers.get(scan_id)
    if subs is not None:
        subs.discard(queue)
        if not subs:
            del _scan_subscribers[scan_id]


def publish(scan_id: str, event_type: str, data: Any) -> None:
    """Broadcast an event to all subscribers of a scan.

    Non-blocking.  If a subscriber's queue is full the event is silently
    dropped (the 30s fallback poll on the frontend will compensate).
    """
    subs = _scan_subscribers.get(scan_id)
    if not subs:
        return
    msg = {"event": event_type, "data": data}
    for queue in list(subs):
        try:
            queue.put_nowait(msg)
        except asyncio.QueueFull:
            pass


def format_sse(event_type: str, data: Any) -> str:
    """Format a single SSE message according to the spec."""
    payload = json.dumps(data, ensure_ascii=False, default=str)
    return f"event: {event_type}\ndata: {payload}\n\n"


SSE_KEEPALIVE = ": keepalive\n\n"
