/**
 * Wails v2 runtime bindings.
 *
 * These types mirror the Wails runtime JS API.  In a live Wails build the
 * actual implementation is injected by the Wails webview host; in Vite dev
 * mode (wails dev) the Wails dev-server bridge provides the same interface.
 *
 * DO NOT edit the shape of these declarations — they must stay in sync with
 * the Wails v2 runtime API documented at https://wails.io/docs/reference/runtime/intro
 */

// The Wails runtime is injected into window.runtime by the webview host.
// We declare it here so TypeScript knows the shape.
declare global {
  interface Window {
    runtime?: WailsRuntime;
    go?: Record<string, Record<string, (...args: unknown[]) => Promise<unknown>>>;
  }
}

interface WailsRuntime {
  EventsEmit(eventName: string, ...data: unknown[]): void;
  EventsOn(eventName: string, callback: (...data: unknown[]) => void): () => void;
  EventsOnce(eventName: string, callback: (...data: unknown[]) => void): void;
  EventsOff(eventName: string, ...additionalEventNames: string[]): void;
  BrowserOpenURL(url: string): void;
  LogDebug(message: string): void;
  LogInfo(message: string): void;
  LogWarning(message: string): void;
  LogError(message: string): void;
}

function runtime(): WailsRuntime {
  if (typeof window !== 'undefined' && window.runtime) return window.runtime;
  // Fallback for hot-reload outside Wails — warn and return no-ops.
  console.warn('[wails] runtime not available — running outside Wails webview');
  return {
    EventsEmit: () => {},
    EventsOn: (_name, _cb) => () => {},
    EventsOnce: () => {},
    EventsOff: () => {},
    BrowserOpenURL: (url) => window.open(url, '_blank'),
    LogDebug: console.debug,
    LogInfo: console.info,
    LogWarning: console.warn,
    LogError: console.error,
  };
}

/** Register a listener for a Wails event.  Returns a cleanup function. */
export function EventsOn(
  eventName: string,
  callback: (...data: unknown[]) => void,
): () => void {
  return runtime().EventsOn(eventName, callback);
}

/** Remove all listeners for the given event name(s). */
export function EventsOff(
  eventName: string,
  ...additional: string[]
): void {
  runtime().EventsOff(eventName, ...additional);
}

/** Open a URL in the system default browser. */
export function BrowserOpenURL(url: string): void {
  runtime().BrowserOpenURL(url);
}
