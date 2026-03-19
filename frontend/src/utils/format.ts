/**
 * Format an ISO date string into a human-readable form.
 */
export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Format byte count into human-readable file size.
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Truncate a string to the given length, appending ellipsis if truncated.
 */
export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 1) + '\u2026';
}

/**
 * Mask an API key, showing only the last 4 characters.
 */
export function maskApiKey(key: string): string {
  if (!key || key.length <= 4) return '****';
  return '*'.repeat(key.length - 4) + key.slice(-4);
}

/**
 * Defang an IOC value for safe display / sharing.
 * - Replaces dots in IPs/domains with [.]
 * - Replaces :// with [://]
 * - Replaces @ in emails with [@]
 */
export function defangIOC(value: string, type?: string): string {
  let defanged = value;
  if (type === 'url' || value.includes('://')) {
    defanged = defanged.replace('://', '[://]');
  }
  if (type === 'ip' || type === 'domain' || type === 'url') {
    defanged = defanged.replace(/\./g, '[.]');
  }
  if (type === 'email' || value.includes('@')) {
    defanged = defanged.replace('@', '[@]');
  }
  return defanged;
}
