import asyncio
import inspect
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, DefaultDict, Dict, List, Optional
from uuid import uuid4

from app.core.logging import get_logger


logger = get_logger("airs.event_bus")

EventHandler = Callable[["Event"], Any]


@dataclass(slots=True)
class Event:
    """Generic application event for in-process pub/sub."""

    topic: str
    payload: Dict[str, Any] = field(default_factory=dict)
    source: str = "airs"
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EventBus:
    """
    Lightweight in-memory event bus for async backend workflows.
    """

    def __init__(self) -> None:
        self._subscribers: DefaultDict[str, List[EventHandler]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def subscribe(self, topic: str, handler: EventHandler) -> None:
        async with self._lock:
            if handler not in self._subscribers[topic]:
                self._subscribers[topic].append(handler)
                logger.info("Event handler subscribed", topic=topic, handler=repr(handler))

    async def unsubscribe(self, topic: str, handler: EventHandler) -> None:
        async with self._lock:
            handlers = self._subscribers.get(topic, [])
            if handler in handlers:
                handlers.remove(handler)
                logger.info("Event handler unsubscribed", topic=topic, handler=repr(handler))
            if not handlers and topic in self._subscribers:
                del self._subscribers[topic]

    async def publish(
        self,
        topic: str,
        payload: Optional[Dict[str, Any]] = None,
        source: str = "airs",
    ) -> Event:
        event = Event(topic=topic, payload=payload or {}, source=source)
        await self._dispatch(event)
        return event

    def publish_nowait(
        self,
        topic: str,
        payload: Optional[Dict[str, Any]] = None,
        source: str = "airs",
    ) -> asyncio.Task:
        return asyncio.create_task(self.publish(topic=topic, payload=payload, source=source))

    async def _dispatch(self, event: Event) -> None:
        handlers = list(self._subscribers.get(event.topic, []))
        wildcard_handlers = list(self._subscribers.get("*", []))
        all_handlers = handlers + wildcard_handlers

        logger.info(
            "Publishing event",
            topic=event.topic,
            source=event.source,
            subscribers=len(all_handlers),
            event_id=event.event_id,
        )

        if not all_handlers:
            return

        results = await asyncio.gather(
            *(self._invoke_handler(handler, event) for handler in all_handlers),
            return_exceptions=True,
        )

        for handler, result in zip(all_handlers, results):
            if isinstance(result, Exception):
                logger.error(
                    "Event handler failed",
                    topic=event.topic,
                    event_id=event.event_id,
                    handler=repr(handler),
                    error=str(result),
                )

    async def _invoke_handler(self, handler: EventHandler, event: Event) -> None:
        result = handler(event)
        if inspect.isawaitable(result):
            await result

    def subscriber_count(self, topic: Optional[str] = None) -> int:
        if topic is not None:
            return len(self._subscribers.get(topic, []))
        return sum(len(handlers) for handlers in self._subscribers.values())


event_bus = EventBus()
