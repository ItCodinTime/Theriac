# WebSocket endpoint (/ws/agent-stream). Streams the agent's live reasoning tokens to the Next.js frontend.

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json

router = APIRouter()

# All active WebSocket connections — Oleh's frontend connects here
_connections: list[WebSocket] = []


@router.websocket("/ws/agent-stream")
async def agent_stream(websocket: WebSocket):
    """
    WebSocket endpoint. Oleh's Next.js terminal connects here to receive
    live reasoning tokens from the Nemotron agent loop.

    Message format sent to frontend:
        {"type": "reasoning", "text": "..."}  — model's thinking (dim/grey in UI)
        {"type": "content",   "text": "..."}  — model's decisions (bright in UI)
    """
    await websocket.accept()
    _connections.append(websocket)
    try:
        while True:
            # Keep connection alive — frontend can send a ping if needed
            await websocket.receive_text()
    except WebSocketDisconnect:
        _connections.remove(websocket)


async def broadcast(message: dict) -> None:
    """
    Sends a message to all connected WebSocket clients.
    Called by the agent route on every StreamToken emitted by the pipeline.
    Dead connections are cleaned up silently.
    """
    payload = json.dumps(message)
    dead: list[WebSocket] = []

    for ws in _connections:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)

    for ws in dead:
        _connections.remove(ws)
