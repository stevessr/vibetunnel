/**
 * Connection Manager for Session View
 *
 * Handles terminal stream connections over WebSocket v3 (single-socket transport)
 * for terminal sessions.
 */

import type { Session } from '../../../shared/types.js';
import { terminalSocketClient } from '../../services/terminal-socket-client.js';
import { createLogger } from '../../utils/logger.js';
import type { Terminal } from '../terminal.js';

const logger = createLogger('connection-manager');

export class ConnectionManager {
  private unsubscribe: (() => void) | null = null;
  private terminal: Terminal | null = null;
  private session: Session | null = null;
  private isConnected = false;
  private stdoutDecoder = new TextDecoder();
  private outputBuffer = '';
  private batchTimeout: number | null = null;
  private onTerminalOutput: ((data: string) => void) | null = null;
  private terminalQueryTail = '';

  constructor(
    private onSessionExit: (sessionId: string) => void,
    private onSessionUpdate: (session: Session) => void
  ) {}

  setOnTerminalOutput(callback: ((data: string) => void) | null): void {
    this.onTerminalOutput = callback;
  }

  setTerminal(terminal: Terminal | null): void {
    this.terminal = terminal;
  }

  setSession(session: Session | null): void {
    this.session = session;
  }

  setConnected(connected: boolean): void {
    this.isConnected = connected;
  }

  connectToStream(): void {
    if (!this.terminal || !this.session) {
      logger.warn(`Cannot connect to stream - missing terminal or session`);
      return;
    }

    // Don't connect if we're already disconnected
    if (!this.isConnected) {
      logger.warn(`Component already disconnected, not connecting to stream`);
      return;
    }

    logger.log(`Connecting to v3 stream for session ${this.session.id}`);

    this.cleanupStreamConnection();

    const flush = () => {
      if (!this.terminal) return;
      if (this.outputBuffer.length > 0) {
        this.terminal.write(this.outputBuffer, true);
        this.outputBuffer = '';
      }
      this.batchTimeout = null;
    };

    const DSR_RESPONSE = '\u001b[?1;2c';

    const respondToPrimaryDeviceAttributeQuery = (chunk: string): void => {
      // fish terminal-compatibility probes terminal capabilities with DA1 query (CSI c).
      // Respond from client-side terminal shim to avoid fish warning/no-feature fallback.
      const combined = `${this.terminalQueryTail}${chunk}`;
      let searchFrom = 0;
      while (searchFrom < combined.length) {
        const queryIndex = combined.indexOf('\u001b[c', searchFrom);
        if (queryIndex === -1) break;
        if (this.session) {
          terminalSocketClient.sendInputText(this.session.id, DSR_RESPONSE);
        }
        searchFrom = queryIndex + 3;
      }

      this.terminalQueryTail = combined.slice(-8);
    };

    const enqueue = (chunk: string) => {
      this.outputBuffer += chunk;
      if (this.batchTimeout === null) {
        this.batchTimeout = window.setTimeout(flush, 16);
      }
    };

    this.unsubscribe = terminalSocketClient.subscribe(this.session.id, {
      stdout: true,
      events: true,
      onStdout: (bytes) => {
        const chunk = this.stdoutDecoder.decode(bytes, { stream: true });
        respondToPrimaryDeviceAttributeQuery(chunk);
        if (this.onTerminalOutput) {
          this.onTerminalOutput(chunk);
        }
        enqueue(chunk);
      },
      onEvent: (event) => {
        if (!this.session) return;

        if (typeof event === 'object' && event !== null) {
          const e = event as {
            type?: string;
            sessionId?: string;
          } & Record<string, unknown>;

          if (e.type === 'session-exit' && e.sessionId === this.session.id) {
            flush();
            this.onSessionExit(this.session.id);
            return;
          }

          if (e.type === 'git-status-update' && e.sessionId === this.session.id) {
            const updatedSession = {
              ...this.session,
              gitModifiedCount:
                (e.gitModifiedCount as number | undefined) ?? this.session.gitModifiedCount,
              gitAddedCount: (e.gitAddedCount as number | undefined) ?? this.session.gitAddedCount,
              gitDeletedCount:
                (e.gitDeletedCount as number | undefined) ?? this.session.gitDeletedCount,
              gitAheadCount: (e.gitAheadCount as number | undefined) ?? this.session.gitAheadCount,
              gitBehindCount:
                (e.gitBehindCount as number | undefined) ?? this.session.gitBehindCount,
            };
            this.session = updatedSession;
            this.onSessionUpdate(updatedSession);
          }
        }
      },
      onError: (message) => {
        logger.debug(`v3 stream error for session ${this.session?.id}: ${message}`);
      },
    });
  }

  cleanupStreamConnection(): void {
    if (this.batchTimeout !== null) {
      clearTimeout(this.batchTimeout);
      this.batchTimeout = null;
    }
    this.outputBuffer = '';
    this.terminalQueryTail = '';
    this.unsubscribe?.();
    this.unsubscribe = null;
  }
}
