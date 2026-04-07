// how-it-works.js — Lightweight "How it works" storytelling layer
//
// Appears on first visit (localStorage-tracked), then accessible from Tools menu.
// Helps new users understand SecPrior value proposition, prioritization logic,
// and typical workflows in under 1 minute.

const HowItWorks = (() => {
  'use strict';

  const STORAGE_KEY = 'cv_how_it_works_seen_v1';
  const FIRST_VISIT_DELAY = 800; // ms — let onboarding complete first

  // ── Public API ─────────────────────────────────────────────────────────────

  function init() {
    // Attach click handler to Tools menu button
    document.getElementById('btn-how-it-works')?.addEventListener('click', show);

    // Attach close handlers
    document.getElementById('how-close')?.addEventListener('click', close);
    document.getElementById('how-got-it')?.addEventListener('click', close);

    // Click outside modal to close
    document.getElementById('modal-how-it-works')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) close();
    });

    // Escape key to close
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('modal-how-it-works');
        if (modal && modal.style.display !== 'none') close();
      }
    });

    // Show on first visit (after onboarding)
    _checkFirstVisit();
  }

  function show() {
    const modal = document.getElementById('modal-how-it-works');
    if (!modal) return;
    modal.style.display = 'flex';
  }

  function close() {
    const modal = document.getElementById('modal-how-it-works');
    if (modal) modal.style.display = 'none';
    localStorage.setItem(STORAGE_KEY, '1');
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  function _checkFirstVisit() {
    // Only show on first visit; localStorage tracks completion
    if (!localStorage.getItem(STORAGE_KEY)) {
      // Small delay to let onboarding overlay complete and transition away
      setTimeout(() => {
        show();
      }, FIRST_VISIT_DELAY);
    }
  }

  return { init, show };
})();
