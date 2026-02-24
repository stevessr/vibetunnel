/**
 * Mobile device detection utilities
 * Provides consistent mobile detection across the application
 */

export type DeviceMode = 'auto' | 'mobile' | 'desktop';

const DEVICE_MODE_STORAGE_KEY = 'vibetunnel_device_mode';

export function getDeviceModePreference(): DeviceMode {
  try {
    const value = localStorage.getItem(DEVICE_MODE_STORAGE_KEY);
    if (value === 'mobile' || value === 'desktop' || value === 'auto') {
      return value;
    }
  } catch {
    // ignore localStorage access errors
  }
  return 'auto';
}

export function setDeviceModePreference(mode: DeviceMode): void {
  try {
    localStorage.setItem(DEVICE_MODE_STORAGE_KEY, mode);
  } catch {
    // ignore localStorage access errors
  }
}

function detectMobileByUA(): boolean {
  return (
    /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) ||
    (!!navigator.maxTouchPoints && navigator.maxTouchPoints > 1) ||
    window.matchMedia?.('(pointer: coarse)').matches
  );
}

/**
 * Detect if the current device should be treated as mobile.
 * Honors explicit user override first, then falls back to UA/capability detection.
 */
export function detectMobile(): boolean {
  const preference = getDeviceModePreference();
  if (preference === 'mobile') return true;
  if (preference === 'desktop') return false;
  return detectMobileByUA();
}

/**
 * Detect if the current device is running iOS.
 *
 * @returns true if the device is running iOS
 */
export function isIOS(): boolean {
  return (
    /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)
  );
}

/**
 * Detect if the current device is running Android.
 *
 * @returns true if the device is running Android
 */
export function isAndroid(): boolean {
  return /Android/i.test(navigator.userAgent);
}

/**
 * Get the mobile platform type.
 *
 * @returns 'ios' | 'android' | 'other' | 'desktop'
 */
export function getMobilePlatform(): 'ios' | 'android' | 'other' | 'desktop' {
  if (!detectMobile()) {
    return 'desktop';
  }

  if (isIOS()) {
    return 'ios';
  }

  if (isAndroid()) {
    return 'android';
  }

  return 'other';
}
