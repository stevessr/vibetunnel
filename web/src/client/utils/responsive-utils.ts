import { detectMobile, getDeviceModePreference } from './mobile-utils.js';

export interface MediaQueryState {
  isMobile: boolean;
  isTablet: boolean;
  isDesktop: boolean;
}

/**
 * Creates a responsive utility that uses ResizeObserver for efficient viewport tracking
 */
export class ResponsiveObserver {
  private callbacks = new Set<(state: MediaQueryState) => void>();
  private currentState: MediaQueryState;
  private resizeObserver: ResizeObserver | null = null;

  constructor() {
    this.currentState = this.getMediaQueryState();

    try {
      // Use ResizeObserver on document.documentElement for efficient viewport tracking
      this.resizeObserver = new ResizeObserver(() => {
        try {
          const newState = this.getMediaQueryState();

          if (this.hasStateChanged(this.currentState, newState)) {
            this.currentState = newState;
            this.notifyCallbacks(newState);
          }
        } catch (error) {
          console.error('Error in ResizeObserver callback:', error);
        }
      });

      this.resizeObserver.observe(document.documentElement);
    } catch (error) {
      console.error('Failed to initialize ResizeObserver:', error);
      // Fallback to window resize events
      this.setupFallbackResizeListener();
    }
  }

  private setupFallbackResizeListener(): void {
    let timeoutId: number;
    const handleResize = () => {
      clearTimeout(timeoutId);
      timeoutId = window.setTimeout(() => {
        const newState = this.getMediaQueryState();
        if (this.hasStateChanged(this.currentState, newState)) {
          this.currentState = newState;
          this.notifyCallbacks(newState);
        }
      }, 100);
    };

    window.addEventListener('resize', handleResize);
  }

  private getMediaQueryState(): MediaQueryState {
    const modePreference = getDeviceModePreference();

    if (modePreference === 'mobile') {
      return {
        isMobile: true,
        isTablet: false,
        isDesktop: false,
      };
    }

    if (modePreference === 'desktop') {
      return {
        isMobile: false,
        isTablet: false,
        isDesktop: true,
      };
    }

    const isMobile = detectMobile();
    if (isMobile) {
      return {
        isMobile: true,
        isTablet: false,
        isDesktop: false,
      };
    }

    return {
      isMobile: false,
      isTablet: false,
      isDesktop: true,
    };
  }

  private hasStateChanged(oldState: MediaQueryState, newState: MediaQueryState): boolean {
    return (
      oldState.isMobile !== newState.isMobile ||
      oldState.isTablet !== newState.isTablet ||
      oldState.isDesktop !== newState.isDesktop
    );
  }

  private notifyCallbacks(state: MediaQueryState): void {
    this.callbacks.forEach((callback) => {
      callback(state);
    });
  }

  subscribe(callback: (state: MediaQueryState) => void): () => void {
    this.callbacks.add(callback);
    // Immediately call with current state
    callback(this.currentState);

    // Return unsubscribe function
    return () => {
      this.callbacks.delete(callback);
    };
  }

  getCurrentState(): MediaQueryState {
    return { ...this.currentState };
  }

  refresh(): void {
    const newState = this.getMediaQueryState();
    if (this.hasStateChanged(this.currentState, newState)) {
      this.currentState = newState;
      this.notifyCallbacks(newState);
    }
  }

  destroy(): void {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }
    this.callbacks.clear();
  }
}

// Singleton instance for global use
export const responsiveObserver = new ResponsiveObserver();
