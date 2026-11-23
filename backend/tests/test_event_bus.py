import pytest
import asyncio
from app.core.event_bus import EventBus, Event, event_bus


@pytest.mark.anyio
async def test_event_bus_exact_publish_subscribe():
    bus = EventBus()
    received = []

    async def async_handler(evt: Event):
        received.append(("async", evt.topic, evt.data))

    def sync_handler(evt: Event):
        received.append(("sync", evt.topic, evt.data))

    bus.subscribe("security.alert", async_handler)
    bus.subscribe("security.alert", sync_handler)

    published = await bus.publish("security.alert", {"severity": "HIGH", "rule": "SQLI_DETECTED"})

    assert published.topic == "security.alert"
    assert published.id.startswith("evt_")
    assert len(received) == 2
    assert ("async", "security.alert", {"severity": "HIGH", "rule": "SQLI_DETECTED"}) in received
    assert ("sync", "security.alert", {"severity": "HIGH", "rule": "SQLI_DETECTED"}) in received


@pytest.mark.anyio
async def test_event_bus_wildcard_subscribe():
    bus = EventBus()
    received = []

    def wildcard_handler(evt: Event):
        received.append(evt.topic)

    bus.subscribe("agent.*", wildcard_handler)

    await bus.publish("agent.tool_call", {"tool": "search_files"})
    await bus.publish("agent.approval_required", {"action": "quarantine"})
    await bus.publish("network.scan_complete", {"found": 0})

    assert len(received) == 2
    assert "agent.tool_call" in received
    assert "agent.approval_required" in received
    assert "network.scan_complete" not in received


@pytest.mark.anyio
async def test_event_bus_unsubscribe():
    bus = EventBus()
    received = []

    def handler(evt: Event):
        received.append(evt.data)

    bus.subscribe("topic.test", handler)
    await bus.publish("topic.test", {"step": 1})
    assert len(received) == 1

    removed = bus.unsubscribe("topic.test", handler)
    assert removed is True

    await bus.publish("topic.test", {"step": 2})
    assert len(received) == 1  # No new event received
