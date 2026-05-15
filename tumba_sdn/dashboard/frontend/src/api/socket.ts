export function createPollingSubscription(callback: () => void, intervalMs = 2500) {
  const timer = window.setInterval(callback, intervalMs);
  return () => window.clearInterval(timer);
}
