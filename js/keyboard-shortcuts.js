// keyboard-shortcuts.js — Keyboard shortcut cheatsheet for ThreatLens
//
// Opens on "?" keypress (handled in app.js) or via Tools menu.
// Lists all global keyboard shortcuts. No localStorage needed —
// always shows on demand, no first-visit tracking.

const KeyboardShortcuts = (() => {
  'use strict';

  // ── Public API ─────────────────────────────────────────────────────────────

  function init() {
    document.getElementById('btn-keyboard-shortcuts')?.addEventListener('click', show);
    document.getElementById('ks-close')?.addEventListener('click', close);

    // Click outside to close
    document.getElementById('modal-keyboard-shortcuts')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) close();
    });

    // Escape to close
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('modal-keyboard-shortcuts');
        if (modal && modal.style.display !== 'none') close();
      }
    });
  }

  function show() {
    const modal = document.getElementById('modal-keyboard-shortcuts');
    if (modal) modal.style.display = 'flex';
  }

  function close() {
    const modal = document.getElementById('modal-keyboard-shortcuts');
    if (modal) modal.style.display = 'none';
  }

  return { init, show };
})();
