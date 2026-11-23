"""backend/app/core/event_bus.py
Asynchronous In-Process Event Bus for AMOJA AI + AgentShield
Provides decoupled, publish-subscribe event routing across the AI Orchestrator,
AgentShield Security Controls, Network Monitor, and Audit Subsystems.
"""

import asyncio
import inspect
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("agentshield.event_bus")


class Event:
    """Represents a discrete event published across the platform."""

    def __init__(
        self,
        topic: str,
        data: Dict[str, Any],
        source: str = "system",
        correlation_id: Optional[str] = None
    ):
        self.id = f"evt_{uuid.uuid4().hex[:12]}"
        self.topic = topic
        self.data = data
        self.source = source
        self.correlation_id = correlation_id or f"corr_{uuid.uuid4().hex[:8]}"
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "topic": self.topic,
            "data": self.data,
            "source": self.source,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp
        }


class EventBus:
    """
    Central in-memory asynchronous publish/subscribe event bus.
    Supports exact topic matches and wildcard subscriptions (e.g. 'security.*').
    """

    def __init__(self):
        self._subscribers: Dict[str, Set[Callable]] = {}
        self._wildcard_subscribers: Dict[str, Set[Callable]] = {}
        self._lock = asyncio.Lock()

    def subscribe(self, topic: str, handler: Callable) -> None:
        """Subscribes a callable (sync or async) to a topic."""
        if "*" in topic:
            prefix = topic.rstrip("*").rstrip(".")
            if prefix not in self._wildcard_subscribers:
                self._wildcard_subscribers[prefix] = set()
            self._wildcard_subscribers[prefix].add(handler)
        else:
            if topic not in self._subscribers:
                self._subscribers[topic] = set()
            self._subscribers[topic].add(handler)
        logger.debug("Subscribed %s to %s", getattr(handler, "__name__", str(handler)), topic)

    def unsubscribe(self, topic: str, handler: Callable) -> bool:
        """Unsubscribes a callable from a topic."""
        removed = False
        if "*" in topic:
            prefix = topic.rstrip("*").rstrip(".")
            if prefix in self._wildcard_subscribers and handler in self._wildcard_subscribers[prefix]:
                self._wildcard_subscribers[prefix].remove(handler)
                removed = True
        else:
            if topic in self._subscribers and handler in self._subscribers[topic]:
                self._subscribers[topic].remove(handler)
                removed = True
        return removed

    async def publish(self, topic: str, data: Dict[str, Any], source: str = "system") -> Event:
        """
        Publishes an event to all matching subscribers asynchronously.
        Catches and logs handler exceptions to prevent subscriber failures from cascading.
        """
        event = Event(topic=topic, data=data, source=source)
        handlers: List[Callable] = []

        # Exact matches
        if topic in self._subscribers:
            handlers.extend(list(self._subscribers[topic]))

        # Wildcard matches (e.g. prefix matches 'security')
        for prefix, subs in self._wildcard_subscribers.items():
            if topic == prefix or topic.startswith(f"{prefix}."):
                handlers.extend(list(subs))

        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as exc:
                logger.error(
                    "Error executing handler %s for event topic '%s': %s",
                    getattr(handler, "__name__", str(handler)),
                    topic,
                    exc,
                    exc_info=True
                )

        return event

    def clear(self) -> None:
        """Clears all registered subscribers."""
        self._subscribers.clear__(self) if hasattr(self, "_subscribers.clear__") else self._subscribers.clear()
        self._wildcard_subscribers.clear()


# Global Singleton Event Bus instance
event_bus = EventBus()

