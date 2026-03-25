// watchlist-modal.js — Modal de gestion de la liste de surveillance

const WatchlistModal = (() => {

  function open() {
    const modal = document.getElementById("modal-watchlist");
    if (!modal) return;
    _render();
    modal.style.display = "flex";
    document.body.style.overflow = "hidden";
    document.getElementById("watchlist-input")?.focus();
  }

  function close() {
    const modal = document.getElementById("modal-watchlist");
    if (modal) modal.style.display = "none";
    document.body.style.overflow = "";
  }

  function _render() {
    const list = Contextualizer.getWatchlist();
    const container = document.getElementById("watchlist-items");
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = `<span style="color:var(--text2);font-size:.8rem">Aucun terme surveillé. Ajoutez des mots-clés ci-dessous.</span>`;
    } else {
      container.innerHTML = list.map(term => `
        <span class="watchlist-tag">
          ${term}
          <button onclick="WatchlistModal.remove('${term.replace(/'/g, "\\'")}')" title="Supprimer">✕</button>
        </span>`).join("");
    }

    _updateBtn();
  }

  function add() {
    const input = document.getElementById("watchlist-input");
    if (!input) return;
    const term = input.value.trim();
    if (!term) return;
    Contextualizer.addToWatchlist(term);
    input.value = "";
    _render();
  }

  function remove(term) {
    Contextualizer.removeFromWatchlist(term);
    _render();
  }

  function _updateBtn() {
    const count = Contextualizer.getWatchlist().length;
    const btn   = document.getElementById("btn-watchlist");
    if (!btn) return;
    btn.classList.toggle("active", count > 0);
    btn.title = count > 0 ? `Watchlist : ${count} terme(s) surveillé(s)` : "Gérer la watchlist";
    const badge = document.getElementById("watchlist-count");
    if (badge) badge.textContent = count > 0 ? ` (${count})` : "";
  }

  function init() {
    document.getElementById("btn-watchlist")?.addEventListener("click", open);
    document.getElementById("watchlist-input")?.addEventListener("keydown", e => {
      if (e.key === "Enter") add();
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape") close();
    });
    _updateBtn();
  }

  return { open, close, add, remove, init };
})();
