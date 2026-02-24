import { execFile } from 'child_process';
import { promisify } from 'util';
import type { MultiplexerSession } from '../../shared/multiplexer-types.js';
import { type SessionCreateOptions, TitleMode } from '../../shared/types.js';
import type { PtyManager } from '../pty/pty-manager.js';
import { createLogger } from '../utils/logger.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('kitty-manager');

export class KittyManager {
  private static instance: KittyManager;
  private ptyManager: PtyManager;

  private constructor(ptyManager: PtyManager) {
    this.ptyManager = ptyManager;
  }

  static getInstance(ptyManager: PtyManager): KittyManager {
    if (!KittyManager.instance) {
      KittyManager.instance = new KittyManager(ptyManager);
    }
    return KittyManager.instance;
  }

  private validateSessionName(name: string): void {
    if (!name || typeof name !== 'string') {
      throw new Error('Session name must be a non-empty string');
    }
    if (!/^[a-zA-Z0-9._-]+$/.test(name)) {
      throw new Error(
        'Session name can only contain letters, numbers, dots, dashes, and underscores'
      );
    }
    if (name.length > 100) {
      throw new Error('Session name too long (max 100 characters)');
    }
  }

  private parseKittyWindowsFromLs(output: string): MultiplexerSession[] {
    try {
      const data = JSON.parse(output) as Array<{
        tabs?: Array<{ windows?: Array<{ id?: number; title?: string; cwd?: string }> }>;
      }>;

      const sessions: MultiplexerSession[] = [];
      for (const osWindow of data) {
        for (const tab of osWindow.tabs ?? []) {
          for (const window of tab.windows ?? []) {
            const id = window.id;
            if (typeof id !== 'number') continue;
            const title = window.title?.trim() || `window-${id}`;
            sessions.push({
              // Use a stable ID-based key for attach/kill operations.
              // Keep human-readable title in activity for display context.
              name: `id:${id}`,
              type: 'kitty',
              windows: 1,
              attached: true,
              current: false,
              activity: title,
              exited: false,
            });
          }
        }
      }
      return sessions;
    } catch {
      return [];
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync('which', ['kitty']);
      return true;
    } catch {
      return false;
    }
  }

  async listSessions(): Promise<MultiplexerSession[]> {
    try {
      const { stdout } = await execFileAsync('kitty', ['@', 'ls'], {
        timeout: 1500,
      });
      return this.parseKittyWindowsFromLs(stdout);
    } catch (error) {
      logger.debug('Failed to list kitty windows', { error });
      return [];
    }
  }

  async createSession(name: string): Promise<void> {
    this.validateSessionName(name);
    try {
      await execFileAsync('kitty', ['@', 'launch', '--type=window', '--title', name]);
      logger.info('Created kitty window session', { name });
    } catch (error) {
      logger.error('Failed to create kitty window session', { name, error });
      throw error;
    }
  }

  private extractWindowId(sessionName: string): string {
    const match = sessionName.match(/^id:(\d+)$/);
    if (!match) {
      throw new Error('Invalid kitty window id. Expected format: id:<number>');
    }
    return match[1];
  }

  async attachToKitty(
    sessionName: string,
    options?: Partial<SessionCreateOptions>
  ): Promise<string> {
    const windowId = this.extractWindowId(sessionName);

    const attachCommand = ['kitty', '@', 'focus-window', '--match', `id:${windowId}`];
    const sessionOptions: SessionCreateOptions = {
      name: `kitty: id:${windowId}`,
      workingDir: options?.workingDir || process.env.HOME || '/',
      cols: options?.cols || 80,
      rows: options?.rows || 24,
      titleMode: options?.titleMode || TitleMode.STATIC,
    };

    const session = await this.ptyManager.createSession(attachCommand, sessionOptions);
    return session.sessionId;
  }

  async killSession(sessionName: string): Promise<void> {
    const windowId = this.extractWindowId(sessionName);

    try {
      await execFileAsync('kitty', ['@', 'close-window', '--match', `id:${windowId}`]);
      logger.info('Killed kitty window session', { sessionName, windowId });
    } catch (error) {
      logger.error('Failed to kill kitty window session', { sessionName, error });
      throw error;
    }
  }

  isInsideKitty(): boolean {
    return !!process.env.KITTY_WINDOW_ID;
  }

  getCurrentSession(): string | null {
    if (!this.isInsideKitty()) return null;

    return process.env.KITTY_WINDOW_ID || null;
  }
}
