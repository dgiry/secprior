// morning-brief.js — Morning Brief generator for ThreatLens
//
// Generates a structured plain-text brief ready to paste into Slack #security,
// Teams, or a morning email.  No new scoring engine — pure aggregation of the
// enriched signals already computed by the pipeline.
//
// Format (scope-aware):
//   🛡️  ThreatLens — Morning Brief
//   📅  Friday, April 5 2026 · 08:45
//   📁  Scope: Last 7 days · 48 articles
//   ━━━ THREAT POSTURE: ELEVATED 🟡
//   🔑  KEV ACTIVE (1)
//   🔴  TOP THREATS (3)
//   👁  WATCHLIST HITS
//   ⚙️  ACTIONABILITY
//
// API:
//   MorningBrief.init(getArticlesFn)      — bind button, store articles getter
//   MorningBrief.show()                   — open modal and generate brief
//   MorningBrief.generate(articles, days) — returns brief string (testable)

const MorningBrief = (() => {
  'use strict';

  let _getArticles    = null;  // () => Article[]
  // _getTrendVPMap removed — per-CVE VP signal unsupported by TV1 API (2026-04)
  let _scopeDays      = 7;     // default scope: last 7 days

  const SEP = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';

  // ── Helpers ────────────────────────────────────────────────────────────────

  function _filterByScope(arts, days) {
    if (!days || days === 0) return arts;
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    return arts.filter(a => a.pubDate && a.pubDate.getTime() >= cutoff);
  }

  function _posture(arts) {
    const critCount = arts.filter(a => a.priorityLevel === 'critical_now').length;
    const invCount  = arts.filter(a => a.priorityLevel === 'investigate').length;
    const kevCount  = arts.filter(a => a.isKEV).length;
    let level, icon, desc;
    if (critCount > 0) {
      level = 'CRITICAL'; icon = '🔴';
      desc  = `${critCount} critical threat${critCount !== 1 ? 's require' : ' requires'} immediate action`;
    } else if (invCount > 5 || kevCount > 2) {
      level = 'HIGH'; icon = '🟠';
      desc  = kevCount > 2
        ? `${kevCount} actively exploited vulnerabilities detected`
        : `${invCount} threats under active investigation`;
    } else if (kevCount > 0 || invCount > 0) {
      level = 'ELEVATED'; icon = '🟡';
      desc  = kevCount > 0
        ? `${kevCount} KEV item${kevCount !== 1 ? 's' : ''} warrant attention`
        : `${invCount} item${invCount !== 1 ? 's' : ''} under investigation`;
    } else {
      level = 'NOMINAL'; icon = '🟢';
      desc  = 'No critical or elevated threats detected';
    }
    return { level, icon, desc, critCount, invCount, kevCount };
  }

  function _fmtDate(d) {
    return d.toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
    });
  }

  function _fmtTime(d) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  // Signal chips for article lines — concise, space-separated
  function _chips(a) {
    const c = [];
    if (a.isKEV)                             c.push('KEV ⚡');
    if ((a.epssScore || 0) > 0)              c.push(`EPSS ${(a.epssScore * 100).toFixed(0)}%`);
    if (a.prioritySignals?.isZeroDay ||
        /zero.?day|0day/i.test(a.title||'')) c.push('0-Day ⏳');
    if (a.isTrending)                        c.push(`Trending×${a.trendingCount || '+'}`);
    if ((a.watchlistMatches || []).length)   c.push('Watchlist 👁');
    return c.join(' · ');
  }

  function _topArticles(arts, max) {
    return [...arts]
      .sort((a, b) =>
        (b.priorityScore || b.score || 0) - (a.priorityScore || a.score || 0))
      .slice(0, max);
  }

  function _kevArticles(arts) {
    return arts
      .filter(a => a.isKEV)
      .sort((a, b) => (b.epssScore || 0) - (a.epssScore || 0))
      .slice(0, 5);
  }

  // Shared watchlist-match predicate — mirrors exec-view.js _isWLMatch.
  // Checks all available signals so both V1 (watchlistMatches) and
  // V2 (watchlistMatchItems / prioritySignals.watchlist) paths are counted.
  function _isWLMatch(a) {
    return (a.watchlistMatches?.length > 0) ||
           (a.watchlistMatchItems?.length > 0) ||
           !!(a.prioritySignals?.watchlist);
  }

  // Aggregate watchlist hits by term name → count.
  // Pulls labels from all available sources in priority order:
  //   1. watchlistMatches (V1 string labels from contextualizer)
  //   2. watchlistMatchItems (V2 full objects from contextualizer)
  //   3. prioritySignals.watchlistItems (scored display items)
  //   4. generic "Watchlist" fallback when a match exists but no labels are available
  function _watchlistTally(arts) {
    const tally = {};
    arts.forEach(a => {
      if (!_isWLMatch(a)) return;
      let labels = [];
      if (a.watchlistMatches?.length > 0) {
        labels = a.watchlistMatches;
      } else if (a.watchlistMatchItems?.length > 0) {
        labels = a.watchlistMatchItems.map(i => i.label || i.value).filter(Boolean);
      } else if (a.prioritySignals?.watchlistItems?.length > 0) {
        labels = a.prioritySignals.watchlistItems.map(i => i.label).filter(Boolean);
      }
      if (labels.length === 0) labels = ['Watchlist'];
      labels.forEach(term => {
        tally[term] = (tally[term] || 0) + 1;
      });
    });
    return Object.entries(tally)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }

  function _actionability(arts) {
    const isZD = a =>
      !!(a.prioritySignals?.isZeroDay ||
         (a.attackTags || []).some(t => t.label === '0-Day') ||
         /zero.?day|0day/i.test(a.title || ''));
    return {
      kev:     arts.filter(a => a.isKEV).length,
      ioc:     arts.filter(a => (a.iocCount || 0) > 0).length,
      cve:     arts.filter(a => (a.cves || []).length > 0).length,
      zeroDay: arts.filter(isZD).length
    };
  }

  // ── Priority action line ──────────────────────────────────────────────────
  // Returns a single analyst-toned recommendation based on the highest-signal
  // condition present in scope. Evaluated in strict priority order.

  function _priorityAction(arts, posture, act, wl) {
    // 1. KEV items that also carry IOC — highest urgency
    const kevWithIOC = arts.filter(a => a.isKEV && (a.iocCount || 0) > 0).length;
    if (kevWithIOC > 0) {
      return `patch ${kevWithIOC} KEV item${kevWithIOC !== 1 ? 's' : ''} immediately — active exploitation indicators present.`;
    }

    // 2. Any KEV — cite up to 2 CVEs for specificity
    if (act.kev > 0) {
      const cveHint = arts
        .filter(a => a.isKEV)
        .flatMap(a => (a.cves || []).slice(0, 1))
        .slice(0, 2)
        .join(', ');
      const suffix = cveHint ? ` (${cveHint})` : '';
      return `patch ${act.kev} actively exploited item${act.kev !== 1 ? 's' : ''}${suffix} — KEV confirmed.`;
    }

    // 3. Critical-priority items with no KEV label
    if (posture.critCount > 0) {
      return `investigate ${posture.critCount} critical-priority item${posture.critCount !== 1 ? 's' : ''} — immediate triage required.`;
    }

    // 4. Multiple IOC-bearing articles
    if (act.ioc >= 3) {
      return `hunt in SIEM/EDR — ${act.ioc} articles carry active indicators of compromise.`;
    }

    // 5. Zero-day
    if (act.zeroDay > 0) {
      return `monitor ${act.zeroDay} zero-day item${act.zeroDay !== 1 ? 's' : ''} — no patch available; apply compensating controls.`;
    }

    // 6. Watchlist hits — name top matched terms
    if (wl.length > 0) {
      const terms = wl.slice(0, 2).map(([t]) => t).join(', ');
      const total = wl.reduce((s, [, c]) => s + c, 0);
      return `review ${total} watchlist-matched article${total !== 1 ? 's' : ''} — terms: ${terms}.`;
    }

    // 7. CVE-linked items with no stronger signal
    if (act.cve > 0) {
      return `apply vendor advisories — ${act.cve} CVE-linked article${act.cve !== 1 ? 's' : ''} in scope.`;
    }

    // 8. Nominal / quiet period
    return `maintain standard monitoring cadence — no elevated threats detected.`;
  }

  // ── Brief generator ────────────────────────────────────────────────────────

  function generate(articles, scopeDays) {
    const days    = scopeDays !== undefined ? scopeDays : _scopeDays;
    const arts    = _filterByScope(articles || [], days);
    const now     = new Date();
    const posture = _posture(arts);
    const kevs    = _kevArticles(arts);
    const top     = _topArticles(arts, 3);
    const wl      = _watchlistTally(arts);
    const act     = _actionability(arts);
    const NUMS    = ['①', '②', '③'];

    const scopeLabel = days === 1  ? 'Last 24h'
                     : days === 7  ? 'Last 7 days'
                     : days === 30 ? 'Last 30 days'
                     : 'All articles';

    // Padding helper for right-aligned counts in actionability block
    const pad = (n, w = 3) => String(n).padStart(w);

    const L = [];  // output lines

    L.push(`🛡️  ThreatLens — Morning Brief`);
    L.push(`📅  ${_fmtDate(now)} · ${_fmtTime(now)}`);
    L.push(`📁  Scope: ${scopeLabel} · ${arts.length} article${arts.length !== 1 ? 's' : ''}`);
    L.push('');
    L.push(SEP);

    // ── Posture ──────────────────────────────────────────────────────────────
    L.push('');
    L.push(`📊  THREAT POSTURE: ${posture.level} ${posture.icon}`);
    L.push(`    ${posture.desc}`);
    L.push(`⚡  Priority action: ${_priorityAction(arts, posture, act, wl)}`);
    L.push('');
    L.push(SEP);

    // ── KEV block ─────────────────────────────────────────────────────────────
    if (kevs.length > 0) {
      L.push('');
      L.push(`🔑  KEV ACTIVE (${kevs.length} item${kevs.length !== 1 ? 's' : ''})`);
      kevs.forEach(a => {
        const cveStr = (a.cves || []).slice(0, 2).join(', ') || '—';
        const epss   = (a.epssScore || 0) > 0
          ? ` · EPSS ${(a.epssScore * 100).toFixed(0)}%`
          : '';
        L.push(`    • ${cveStr}${epss}`);
        L.push(`      ${a.title.slice(0, 88)}${a.title.length > 88 ? '…' : ''}`);
      });
      L.push('');
      L.push(SEP);
    }

    // ── Top threats block ─────────────────────────────────────────────────────
    if (top.length > 0) {
      L.push('');
      L.push(`🔴  TOP THREATS (${top.length})`);
      top.forEach((a, i) => {
        const chips = _chips(a);
        const score = a.priorityScore || a.score || '—';
        L.push('');
        L.push(`    ${NUMS[i] || (i + 1 + '.')}  ${a.title.slice(0, 86)}${a.title.length > 86 ? '…' : ''}`);
        if (chips) L.push(`        ${chips}`);
        L.push(`        Score ${score} · ${a.sourceName || a.source}`);
        if (a.link) L.push(`        → ${a.link}`);
      });
      L.push('');
      L.push(SEP);
    }

    // ── Watchlist block ───────────────────────────────────────────────────────
    if (wl.length > 0) {
      L.push('');
      L.push(`👁  WATCHLIST HITS (${wl.length} term${wl.length !== 1 ? 's' : ''})`);
      wl.forEach(([term, count]) => {
        L.push(`    • ${term}: ${count} article${count !== 1 ? 's' : ''}`);
      });
      L.push('');
      L.push(SEP);
    }

    // ── Actionability block ───────────────────────────────────────────────────
    L.push('');
    L.push('⚙️  ACTIONABILITY');
    L.push(`    🔑  Patch immediately  (KEV):  ${pad(act.kev)}`);
    L.push(`    🔍  Hunt in SIEM/EDR   (IOC):  ${pad(act.ioc)}`);
    L.push(`    📋  Apply advisory     (CVE):  ${pad(act.cve)}`);
    L.push(`    ⏳  Zero-day — monitor       :  ${pad(act.zeroDay)}`);
    // VP line removed — per-CVE signal unsupported by TV1 API (2026-04)
    L.push('');
    L.push(SEP);

    // ── Footer ────────────────────────────────────────────────────────────────
    L.push('');
    L.push(`Generated by ThreatLens · ${now.toISOString().slice(0, 16).replace('T', ' ')} UTC`);
    L.push('#threatintel #security #standup');

    return L.join('\n');
  }

  // ── Modal helpers ──────────────────────────────────────────────────────────

  function _refresh() {
    const ta = document.getElementById('mb-textarea');
    if (!ta) return;
    const articles = _getArticles ? _getArticles() : [];
    ta.value = generate(articles, _scopeDays);
  }

  function _copy() {
    const ta = document.getElementById('mb-textarea');
    if (!ta) return;
    const text = ta.value;
    const btn  = document.getElementById('mb-copy-btn');

    const flash = (msg) => {
      if (!btn) return;
      const orig = btn.textContent;
      btn.textContent = msg;
      setTimeout(() => { btn.textContent = orig; }, 1800);
    };

    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text)
        .then(() => flash('✅ Copied!'))
        .catch(() => { ta.select(); document.execCommand('copy'); flash('✅ Copied!'); });
    } else {
      ta.select();
      document.execCommand('copy');
      flash('✅ Copied!');
    }
  }

  function _close() {
    const modal = document.getElementById('modal-morning-brief');
    if (modal) modal.style.display = 'none';
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  function show() {
    const modal = document.getElementById('modal-morning-brief');
    if (!modal) return;
    _refresh();
    modal.style.display = 'flex';
  }

  function init(getArticlesFn) {
    _getArticles   = getArticlesFn;

    document.getElementById('btn-morning-brief')?.addEventListener('click', show);
    document.getElementById('mb-close')?.addEventListener('click', _close);
    document.getElementById('mb-copy-btn')?.addEventListener('click', _copy);

    // Click outside overlay to close
    document.getElementById('modal-morning-brief')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) _close();
    });

    // Scope pills
    document.querySelectorAll('#mb-scope-pills .mb-scope-pill').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        _scopeDays = parseInt(btn.dataset.days) || 0;
        document.querySelectorAll('#mb-scope-pills .mb-scope-pill')
          .forEach(b => b.classList.toggle('mb-scope-active', b === btn));
        _refresh();
      });
    });

    // ESC key
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('modal-morning-brief');
        if (modal && modal.style.display !== 'none') _close();
      }
    });
  }

  return { init, show, generate };
})();
