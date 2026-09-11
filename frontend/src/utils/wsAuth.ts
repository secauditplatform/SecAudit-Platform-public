/** Send first-frame WebSocket auth (tokens must not appear in URL query strings). */
export function authenticateWebSocket(ws: WebSocket, token: string | null, authEnabled: boolean): void {
  if (authEnabled && token) {
    ws.send(JSON.stringify({ type: "auth", token }));
  }
}
