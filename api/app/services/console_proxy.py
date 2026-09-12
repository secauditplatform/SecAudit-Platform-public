"""Proxy the browser WebSocket to the console sandbox container."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed

logger = logging.getLogger(__name__)


def sandbox_console_ws_url(base_url: str) -> str:
    """Build sandbox WS URL without putting tokens in the query string."""
    base = base_url.rstrip("/")
    if base.startswith("http://"):
        base = "ws://" + base[len("http://") :]
    elif base.startswith("https://"):
        base = "wss://" + base[len("https://") :]
    elif not base.startswith(("ws://", "wss://")):
        base = "ws://" + base
    return f"{base}/api/v1/ws/console"


async def proxy_console_websocket(
    client: WebSocket,
    *,
    sandbox_url: str,
    token: str | None = None,
) -> None:
    """Bridge bytes/text to the sandbox service (client already authenticated).

    Auth to the sandbox is sent as the first JSON frame ``{"type":"auth","token":...}``
    — never as a query parameter (avoids proxy/access-log leakage).
    """
    upstream_url = sandbox_console_ws_url(sandbox_url)

    try:
        async with ws_connect(upstream_url, open_timeout=10) as upstream:
            if token:
                await upstream.send(json.dumps({"type": "auth", "token": token}))

            async def client_to_upstream() -> None:
                try:
                    while True:
                        message = await client.receive()
                        if message["type"] == "websocket.disconnect":
                            await upstream.close()
                            return
                        if "text" in message:
                            await upstream.send(message["text"])
                        elif "bytes" in message:
                            await upstream.send(message["bytes"])
                except WebSocketDisconnect:
                    await upstream.close()
                except Exception:
                    logger.exception("console proxy client→upstream failed")
                    await upstream.close()

            async def upstream_to_client() -> None:
                try:
                    async for message in upstream:
                        if isinstance(message, bytes):
                            await client.send_bytes(message)
                        else:
                            await client.send_text(message)
                except ConnectionClosed:
                    pass
                except Exception:
                    logger.exception("console proxy upstream→client failed")
                finally:
                    try:
                        await client.close()
                    except Exception:
                        pass

            await asyncio.gather(client_to_upstream(), upstream_to_client())
    except Exception as exc:
        logger.warning("console sandbox unreachable: %s", exc)
        try:
            await client.send_text(
                "\r\n\x1b[31mConsole sandbox unavailable. "
                "Check the console service health.\x1b[0m\r\n"
            )
        except Exception:
            pass
        try:
            await client.close(code=1011, reason="Console sandbox unavailable")
        except Exception:
            pass
