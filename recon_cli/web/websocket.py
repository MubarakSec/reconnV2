"""
WebSocket Server for Real-Time Updates.

Provides real-time communication for:
- Job status updates
- Scan progress
- Live findings
- System alerts

Example:
    >>> from recon_cli.web.websocket import WebSocketManager
    >>> manager = WebSocketManager()
    >>> await manager.broadcast({"type": "job_update", "data": {...}})
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from weakref import WeakSet

try:
    from fastapi import WebSocket, WebSocketDisconnect
    from starlette.websockets import WebSocketState
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    WebSocket = Any
    WebSocketDisconnect = Exception

__all__ = [
    "MessageType",
    "Message",
    "WebSocketClient",
    "ConnectionManager",
    "WebSocketManager",
    "EventBus",
    "broadcast_update",
    "create_websocket_router",
]


logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of WebSocket messages."""
    
    # Job events
    JOB_CREATED = "job_created"
    JOB_STARTED = "job_started"
    JOB_PROGRESS = "job_progress"
    JOB_COMPLETED = "job_completed"
    JOB_FAILED = "job_failed"
    JOB_CANCELLED = "job_cancelled"
    
    # Stage events
    STAGE_STARTED = "stage_started"
    STAGE_PROGRESS = "stage_progress"
    STAGE_COMPLETED = "stage_completed"
    STAGE_FAILED = "stage_failed"
    
    # Finding events
    FINDING_NEW = "finding_new"
    FINDING_BATCH = "finding_batch"
    
    # System events
    SYSTEM_STATUS = "system_status"
    SYSTEM_ALERT = "system_alert"
    SYSTEM_ERROR = "system_error"
    
    # Connection events
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    HEARTBEAT = "heartbeat"
    
    # Custom
    CUSTOM = "custom"


@dataclass
class Message:
    """WebSocket message structure."""
    
    type: MessageType
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    channel: str = "default"
    id: Optional[str] = None
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps({
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "channel": self.channel,
            "id": self.id,
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> "Message":
        """Parse from JSON string."""
        data = json.loads(json_str)
        return cls(
            type=MessageType(data.get("type", "custom")),
            data=data.get("data", {}),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(),
            channel=data.get("channel", "default"),
            id=data.get("id"),
        )
    
    @classmethod
    def job_progress(cls, job_id: str, progress: float, stage: str = "") -> "Message":
        """Create job progress message."""
        return cls(
            type=MessageType.JOB_PROGRESS,
            data={"job_id": job_id, "progress": progress, "stage": stage},
        )
    
    @classmethod
    def finding(cls, job_id: str, finding: Dict[str, Any]) -> "Message":
        """Create new finding message."""
        return cls(
            type=MessageType.FINDING_NEW,
            data={"job_id": job_id, "finding": finding},
        )
    
    @classmethod
    def alert(cls, level: str, message: str, details: Optional[Dict] = None) -> "Message":
        """Create system alert message."""
        return cls(
            type=MessageType.SYSTEM_ALERT,
            data={"level": level, "message": message, "details": details or {}},
        )


@dataclass
class WebSocketClient:
    """Represents a connected WebSocket client."""
    
    websocket: WebSocket
    client_id: str
    connected_at: datetime = field(default_factory=datetime.now)
    subscriptions: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    async def send(self, message: Message) -> bool:
        """Send message to client."""
        try:
            if HAS_FASTAPI and self.websocket.client_state == WebSocketState.CONNECTED:
                await self.websocket.send_text(message.to_json())
                return True
        except Exception as e:
            logger.error(f"Failed to send to client {self.client_id}: {e}")
        return False
    
    def is_subscribed(self, channel: str) -> bool:
        """Check if client is subscribed to channel."""
        return channel in self.subscriptions or "all" in self.subscriptions


class ConnectionManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        self._clients: Dict[str, WebSocketClient] = {}
        self._channels: Dict[str, Set[str]] = {}  # channel -> client_ids
        self._lock = asyncio.Lock()
    
    @property
    def client_count(self) -> int:
        """Get number of connected clients."""
        return len(self._clients)
    
    async def connect(
        self,
        websocket: WebSocket,
        client_id: str,
        channels: Optional[List[str]] = None,
    ) -> WebSocketClient:
        """Accept and register a new connection."""
        if HAS_FASTAPI:
            await websocket.accept()
        
        client = WebSocketClient(
            websocket=websocket,
            client_id=client_id,
            subscriptions=set(channels or ["default"]),
        )
        
        async with self._lock:
            self._clients[client_id] = client
            
            # Register channel subscriptions
            for channel in client.subscriptions:
                if channel not in self._channels:
                    self._channels[channel] = set()
                self._channels[channel].add(client_id)
        
        logger.info(f"Client connected: {client_id}")
        
        # Send welcome message
        await client.send(Message(
            type=MessageType.CONNECTED,
            data={"client_id": client_id, "channels": list(client.subscriptions)},
        ))
        
        return client
    
    async def disconnect(self, client_id: str) -> None:
        """Disconnect and unregister a client."""
        async with self._lock:
            client = self._clients.pop(client_id, None)
            if client:
                # Remove from channels
                for channel in client.subscriptions:
                    if channel in self._channels:
                        self._channels[channel].discard(client_id)
                        if not self._channels[channel]:
                            del self._channels[channel]
        
        logger.info(f"Client disconnected: {client_id}")
    
    async def subscribe(self, client_id: str, channel: str) -> bool:
        """Subscribe client to a channel."""
        async with self._lock:
            client = self._clients.get(client_id)
            if client:
                client.subscriptions.add(channel)
                if channel not in self._channels:
                    self._channels[channel] = set()
                self._channels[channel].add(client_id)
                return True
        return False
    
    async def unsubscribe(self, client_id: str, channel: str) -> bool:
        """Unsubscribe client from a channel."""
        async with self._lock:
            client = self._clients.get(client_id)
            if client:
                client.subscriptions.discard(channel)
                if channel in self._channels:
                    self._channels[channel].discard(client_id)
                return True
        return False
    
    async def send_to_client(self, client_id: str, message: Message) -> bool:
        """Send message to specific client."""
        client = self._clients.get(client_id)
        if client:
            return await client.send(message)
        return False
    
    async def broadcast(self, message: Message) -> int:
        """Broadcast message to all subscribed clients."""
        sent_count = 0
        channel = message.channel
        
        async with self._lock:
            client_ids = self._channels.get(channel, set()).copy()
            # Also include clients subscribed to "all"
            client_ids.update(self._channels.get("all", set()))
        
        for client_id in client_ids:
            client = self._clients.get(client_id)
            if client and await client.send(message):
                sent_count += 1
        
        return sent_count
    
    async def broadcast_to_all(self, message: Message) -> int:
        """Broadcast message to all connected clients."""
        sent_count = 0
        
        for client in list(self._clients.values()):
            if await client.send(message):
                sent_count += 1
        
        return sent_count
    
    def get_client(self, client_id: str) -> Optional[WebSocketClient]:
        """Get client by ID."""
        return self._clients.get(client_id)
    
    def get_channel_clients(self, channel: str) -> List[WebSocketClient]:
        """Get all clients subscribed to a channel."""
        client_ids = self._channels.get(channel, set())
        return [
            self._clients[cid]
            for cid in client_ids
            if cid in self._clients
        ]


EventHandler = Callable[[Message], None]


class EventBus:
    """Pub/sub event bus for internal events."""
    
    def __init__(self):
        self._handlers: Dict[MessageType, List[EventHandler]] = {}
        self._async_handlers: Dict[MessageType, List[Callable]] = {}
    
    def subscribe(self, event_type: MessageType, handler: EventHandler) -> None:
        """Subscribe to an event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    def subscribe_async(self, event_type: MessageType, handler: Callable) -> None:
        """Subscribe async handler to an event type."""
        if event_type not in self._async_handlers:
            self._async_handlers[event_type] = []
        self._async_handlers[event_type].append(handler)
    
    def unsubscribe(self, event_type: MessageType, handler: EventHandler) -> None:
        """Unsubscribe from an event type."""
        if event_type in self._handlers:
            self._handlers[event_type].remove(handler)
    
    def publish(self, message: Message) -> None:
        """Publish an event synchronously."""
        handlers = self._handlers.get(message.type, [])
        for handler in handlers:
            try:
                handler(message)
            except Exception as e:
                logger.error(f"Event handler error: {e}")
    
    async def publish_async(self, message: Message) -> None:
        """Publish an event asynchronously."""
        # Sync handlers
        self.publish(message)
        
        # Async handlers
        handlers = self._async_handlers.get(message.type, [])
        tasks = [handler(message) for handler in handlers]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


class WebSocketManager:
    """High-level WebSocket manager with event bus."""
    
    _instance: Optional["WebSocketManager"] = None
    
    def __new__(cls) -> "WebSocketManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.connections = ConnectionManager()
        self.event_bus = EventBus()
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._heartbeat_interval = 30.0
        self._initialized = True
    
    async def start(self) -> None:
        """Start the WebSocket manager."""
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("WebSocket manager started")
    
    async def stop(self) -> None:
        """Stop the WebSocket manager."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        logger.info("WebSocket manager stopped")
    
    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        while True:
            try:
                await asyncio.sleep(self._heartbeat_interval)
                await self.connections.broadcast_to_all(
                    Message(type=MessageType.HEARTBEAT, data={"time": datetime.now().isoformat()})
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    async def handle_connection(
        self,
        websocket: WebSocket,
        client_id: str,
        channels: Optional[List[str]] = None,
    ) -> None:
        """Handle a WebSocket connection lifecycle."""
        client = await self.connections.connect(websocket, client_id, channels)
        
        try:
            while True:
                if HAS_FASTAPI:
                    data = await websocket.receive_text()
                    message = Message.from_json(data)
                    await self._handle_message(client, message)
                else:
                    await asyncio.sleep(1)
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.error(f"Connection error for {client_id}: {e}")
        finally:
            await self.connections.disconnect(client_id)
    
    async def _handle_message(self, client: WebSocketClient, message: Message) -> None:
        """Handle incoming message from client."""
        # Handle built-in message types
        if message.type == MessageType.HEARTBEAT:
            await client.send(Message(type=MessageType.HEARTBEAT))
        else:
            # Publish to event bus
            await self.event_bus.publish_async(message)
    
    async def broadcast(
        self,
        message_type: MessageType,
        data: Dict[str, Any],
        channel: str = "default",
    ) -> int:
        """Broadcast a message to subscribed clients."""
        message = Message(type=message_type, data=data, channel=channel)
        count = await self.connections.broadcast(message)
        
        # Also publish to event bus
        await self.event_bus.publish_async(message)
        
        return count
    
    async def notify_job_progress(
        self,
        job_id: str,
        progress: float,
        stage: str = "",
        details: Optional[Dict] = None,
    ) -> None:
        """Send job progress update."""
        await self.broadcast(
            MessageType.JOB_PROGRESS,
            {
                "job_id": job_id,
                "progress": progress,
                "stage": stage,
                "details": details or {},
            },
            channel=f"job:{job_id}",
        )
    
    async def notify_finding(
        self,
        job_id: str,
        finding: Dict[str, Any],
    ) -> None:
        """Send new finding notification."""
        await self.broadcast(
            MessageType.FINDING_NEW,
            {"job_id": job_id, "finding": finding},
            channel=f"job:{job_id}",
        )
    
    async def notify_alert(
        self,
        level: str,
        message: str,
        details: Optional[Dict] = None,
    ) -> None:
        """Send system alert."""
        await self.broadcast(
            MessageType.SYSTEM_ALERT,
            {"level": level, "message": message, "details": details or {}},
            channel="alerts",
        )


# Global manager instance
_manager: Optional[WebSocketManager] = None


def get_websocket_manager() -> WebSocketManager:
    """Get the global WebSocket manager instance."""
    global _manager
    if _manager is None:
        _manager = WebSocketManager()
    return _manager


async def broadcast_update(
    message_type: MessageType,
    data: Dict[str, Any],
    channel: str = "default",
) -> int:
    """Broadcast update using global manager."""
    manager = get_websocket_manager()
    return await manager.broadcast(message_type, data, channel)


def create_websocket_router():
    """Create FastAPI router for WebSocket endpoints."""
    if not HAS_FASTAPI:
        raise ImportError("FastAPI is required for WebSocket router")
    
    from fastapi import APIRouter, Query
    
    router = APIRouter(prefix="/ws", tags=["websocket"])
    manager = get_websocket_manager()
    
    @router.websocket("/connect")
    async def websocket_endpoint(
        websocket: WebSocket,
        client_id: str = Query(""),
        channels: str = Query("default"),
    ):
        """WebSocket connection endpoint."""
        if not client_id:
            client_id = "anonymous"
        channel_list = [c.strip() for c in channels.split(",") if c.strip()]
        await manager.handle_connection(websocket, client_id, channel_list)
    
    @router.websocket("/job/{job_id}")
    async def job_websocket(
        websocket: WebSocket,
        job_id: str,
        client_id: str = Query(""),
    ):
        """WebSocket for specific job updates."""
        if not client_id:
            client_id = "anonymous"
        await manager.handle_connection(
            websocket,
            client_id,
            channels=[f"job:{job_id}", "alerts"],
        )
    
    return router
