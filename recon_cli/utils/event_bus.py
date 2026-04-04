from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Union


class PipelineEventBus:
    """
    In-Memory Event Bus for Real-time Stage Triggers.
    Allows stages to publish findings and other stages to consume them immediately.
    Supports both Queue-based subscriptions (for async iterators) and 
    Callback-based subscriptions (for real-time tracking).
    """

    def __init__(self):
        # type -> list of queues
        self._subscribers: Dict[str, List[asyncio.Queue]] = defaultdict(list)
        # All events for global subscribers
        self._all_subscribers: List[asyncio.Queue] = []
        
        # type -> list of callbacks
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._all_callbacks: List[Callable] = []
        
        self._lock = asyncio.Lock()
        self._event_count = 0

    async def publish(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publish an event to all interested subscribers."""
        self._event_count += 1
        payload = {"type": event_type, "data": data, "index": self._event_count}

        # Publish to specific type queue subscribers
        for queue in self._subscribers.get(event_type, []):
            await queue.put(payload)

        # Publish to 'all' queue subscribers
        for queue in self._all_subscribers:
            await queue.put(payload)
            
        # Publish to specific type callbacks
        for callback in self._callbacks.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception:
                pass
                
        # Publish to 'all' callbacks
        for callback in self._all_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception:
                pass

    def subscribe(
        self, 
        event_types: Optional[Union[List[str], str]] = None, 
        callback: Optional[Callable] = None
    ) -> Optional[asyncio.Queue]:
        """
        Subscribe to specific event types or all events.
        If callback is provided, it will be called directly.
        Otherwise, returns a queue where events will be pushed.
        """
        # Convert single string to list
        if isinstance(event_types, str):
            event_types = [event_types]
            
        if callback:
            if event_types is None:
                self._all_callbacks.append(callback)
            else:
                for etype in event_types:
                    self._callbacks[etype].append(callback)
            return None

        queue = asyncio.Queue()  # type: ignore[var-annotated]
        if event_types is None:
            self._all_subscribers.append(queue)
        else:
            for etype in event_types:
                self._subscribers[etype].append(queue)
        return queue

    async def unsubscribe(self, subscriber: Union[asyncio.Queue, Callable]) -> None:
        """Remove a subscriber (either a queue or a callback)."""
        async with self._lock:
            if isinstance(subscriber, asyncio.Queue):
                # Remove from type-specific lists
                for etypes in self._subscribers.values():
                    if subscriber in etypes:
                        etypes.remove(subscriber)

                # Remove from global list
                if subscriber in self._all_subscribers:
                    self._all_subscribers.remove(subscriber)
            else:
                # Remove from type-specific callbacks
                for cbs in self._callbacks.values():
                    if subscriber in cbs:
                        cbs.remove(subscriber)
                
                # Remove from global list
                if subscriber in self._all_callbacks:
                    self._all_callbacks.remove(subscriber)
