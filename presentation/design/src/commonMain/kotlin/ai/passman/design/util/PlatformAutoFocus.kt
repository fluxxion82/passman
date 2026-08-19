package ai.passman.design.util

/**
 * Whether a form screen should focus its first field as soon as it appears.
 *
 * True only on desktop, where a fresh screen otherwise needs a mouse click before the keyboard
 * (Tab / Enter via `formKeyboardNavigation`) can do anything. Mobile stays false: auto-focusing
 * a field there pops the soft keyboard over a screen the user has not touched yet.
 */
expect val autoFocusFormOnShow: Boolean
