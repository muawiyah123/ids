/**
 * src/hooks/useRealtimeEvents.ts
 *
 * WebSocket hook for real-time detection/alert events.
 * Auto-reconnects with exponential backoff.
 * Stores the last N events for display.
 */
import { useEffect, useRef, useState, useCallback } from 'react';
import { getWebSocketUrl } from '../services/api';
import { useAuthStore } from '../stores/authStore';
import type { WsEvent } from '../types';

const MAX_EVENTS = 100;
const MAX_BACKOFF_MS = 15000;
const INITIAL_BACKOFF_MS = 1000;

export interface RealtimeState {
  isConnected: boolean;
  events: WsEvent[];
  lastEvent: WsEvent | null;
}

export function useRealtimeEvents(enabled = true): RealtimeState {
  const [isConnected, setIsConnected] = useState(false);
  const [events, setEvents] = useState<WsEvent[]>([]);
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef(INITIAL_BACKOFF_MS);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const accessToken = useAuthStore((state) => state.accessToken);

  const connect = useCallback(() => {
    if (!enabled) return;
    const token = accessToken || useAuthStore.getState().accessToken;
    if (!token) return;

    const url = getWebSocketUrl(token);

    if (wsRef.current) {
      try { wsRef.current.close(); } catch {}
      wsRef.current = null;
    }

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        backoffRef.current = INITIAL_BACKOFF_MS;
      };

      ws.onmessage = (e) => {
        try {
          const event: WsEvent = JSON.parse(e.data);
          if (event.type === 'connection.established' || event.type === 'pong') return;
          setLastEvent(event);
          setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS));
        } catch {
          // ignore parse errors
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        wsRef.current = null;
        if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
        reconnectTimer.current = setTimeout(() => {
          backoffRef.current = Math.min(backoffRef.current * 1.5, MAX_BACKOFF_MS);
          connect();
        }, backoffRef.current);
      };

      ws.onerror = () => {
        try { ws.close(); } catch {}
      };
    } catch (err) {
      console.warn('WS connect error:', err);
    }
  }, [enabled, accessToken]);

  useEffect(() => {
    if (!enabled) return;
    const t = setTimeout(connect, 150);
    return () => {
      clearTimeout(t);
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        try { wsRef.current.close(); } catch {}
        wsRef.current = null;
      }
    };
  }, [connect, enabled, accessToken]);

  return { isConnected, events, lastEvent };
}
