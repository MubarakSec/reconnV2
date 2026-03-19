from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Dict, List, Set, Optional, Callable


class PipelineEventBus:
    """
    In-Memory Event Bus for Real-time Stage Triggers.
    Allows stages to publish findings and other stages to consume them immediately.
    """

    def __init__(self):
        # type -> list of queues
        self._subscribers: Dict[str, List[asyncio.Queue]] = defaultdict(list)
        # All events for global subscribers
        self._all_subscribers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        self._event_count = 0

    async def publish(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publish an event to all interested subscribers."""
        self._event_count += 1
        payload = {"type": event_type, "data": data, "index": self._event_count}
        
        # Publish to specific type subscribers
        for queue in self._subscribers.get(event_type, []):
            await queue.put(payload)
            
        # Publish to 'all' subscribers
        for queue in self._all_subscribers:
            await queue.put(payload)

    def subscribe(self, event_types: Optional[List[str]] = None) -> asyncio.Queue:
        """
        Subscribe to specific event types or all events.
        Returns a queue where events will be pushed.
        """
        queue = asyncio.Queue()
        if event_types is None:
            self._all_subscribers.append(queue)
        else:
            for etype in event_types:
                self._subscribers[etype].append(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Remove a subscriber."""
        async with self._lock:
            # Remove from type-specific lists
            for etypes in self._subscribers.values():
                if queue in etypes:
                    etypes.remove(queue)
            
            # Remove from global list
            if queue in self._all_subscribers:
                self._all_subscribers.remove(queue)
