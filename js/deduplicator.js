// deduplicator.js — Stage 3 : Déduplication hybride
//
// Architecture en 6 couches :
//   1. normalizeTitle  — minuscules, déaccent, ponctuation, variantes sécurité
//   2. tokenizeTitle   — tokens significatifs (garde CVE, vendors, termes sécu)
//   3. jaccardSimilarity — score [0–1] sur ensembles de tokens
//   4. compareArticles — signaux complets (CVE, vendor, product, date, URL)
//   5. classifyDuplicate — décision : "duplicate" | "related" | "distinct"
//   6. deduplicate     — pipeline : fusionner les doublons, lier les incidents
//
// Seuils configurables via CONFIG.THRESHOLDS
// Tests intégrés : Deduplicator.runTests()

const Deduplicator = (() => {

  // ═══════════════════════════════════════════════════════════════════════════
  // CONFIG — seuils et paramètres modifiables
  // ═══════════════════════════════════════════════════════════════════════════

  const CONFIG = {
    THRESHOLDS: {
      DUPLICATE: 0.85,  // >= → quasi-doublon (avec garde-fous)
      RELATED:   0.65   // >= et < DUPLICATE → incident lié (avec garde-fous)
    },
    CLOSE_IN_TIME_MS: 7 * 24 * 3600 * 1000  // 7 jours
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // LISTES DE RÉFÉRENCE
  // ═══════════════════════════════════════════════════════════════════════════

  // Mots vides : trop fréquents pour aider la comparaison.
  // Inclut les synonymes de "vulnerability" (flaw, bug, issue…) pour que deux
  // articles sur le même sujet mais avec des termes différents restent proches.
  const STOP_WORDS = new Set([
    // Articles / prépositions / conjonctions
    'the','a','an','in','of','on','for','with','and','or','is','to','by','via',
    'at','as','from','into','than','that','this','these','those','be','been',
    'its','it','are','was','has','have','had','not','but','can','may','will',
    // Verbes génériques d'actualité (réduisent le signal entre sources)
    'warns','warn','says','say','reports','report','releases','release',
    'discloses','disclose','disclosed','fixes','fix','fixed','patches','patch',
    'patched','unpatched','publishes','publish','published','discovers','discover',
    'finds','find','alerts','alert','confirms','confirm','details','detail',
    'announces','announce','adds','add','updates','update','updated',
    // Adjectifs/noms génériques sécurité — synonymes réduisent la précision Jaccard
    'critical','severe','serious','important','high','medium','low',
    'vulnerability','vulnerabilities','flaw','flaws','bug','bugs',
    'issue','issues','defect','weakness','hole',
    'security','breach','attack','attacks','threat','threats','risk','risks',
    'new','latest','recent','actively','multiple','several',
    // Adverbes / qualificatifs temporels sans valeur distinctive
    'also','about','after','all','any','back','before','between','both','could',
    'does','during','each','even','first','gets','given','here','however','just',
    'known','like','make','making','many','might','more','most','much','now',
    'only','other','own','public','same','second','since','some','still','such',
    'there','they','through','too','under','up','us','use','used','using','very',
    'when','where','while','who','would','yet','your','then','been','what','wild',
    // Français
    'le','la','les','de','du','des','en','et','ou','un','une','sur','par',
    'dans','au','aux','ce','qui','que','est','son','ses','avec','pour','plus',
    'tout','tous','toutes','cette','cet','ces','leur','leurs','lors','via',
    'afin','donc','ainsi','mais','selon','après','avant','entre','contre'
  ]);

  // Termes de sécurité importants : toujours conservés même si courts.
  // Distinguent des étapes différentes d'un incident (advisory ≠ PoC ≠ KEV).
  const SECURITY_TERMS = new Set([
    // Vulnérabilités / types
    'rce','lpe','sqli','xss','csrf','xxe','ssrf','idor','ssti','rop','oob',
    '0day','zeroday','poc','kev','epss','cvss',
    // Actions / événements (conservés pour discriminer les étapes d'un incident)
    'advisory','exploit','exploitation','exploited','exploiting','exploitable',
    'backdoor','rootkit','ransomware','malware','spyware','trojan','worm',
    'apt','c2','botnet','phishing','spearphishing',
    // Techniques
    'bypass','injection','overflow','underflow','unauthenticated','unauth',
    'authentication','execution','escalation','privesc','disclosure','exposed',
    'leaked','stolen','remote','local','arbitrary','command',
    // Contexte opérationnel
    'supplychain','inthewild','outofband','zeroday','emergency','workaround',
    'mitigate','mitigation'
  ]);

  // Vendeurs + produits connus (pour détecter sameVendor / sameProduct).
  // Clé = token normalisé.
  const VENDORS = new Set([
    // Microsoft
    'microsoft','windows','office','azure','exchange','sharepoint','teams',
    'defender','activedirectory','mshtml','print','spooler','rdp','rpc',
    // Google / Alphabet
    'google','chrome','chromium','android','workspace','v8',
    // Apple
    'apple','ios','macos','safari','iphone','ipad','webkit','tvos','watchos',
    // Amazon / AWS
    'amazon','aws','s3','ec2','lambda','cloudfront',
    // Meta
    'meta','facebook','instagram','whatsapp',
    // Réseau / Sécurité réseau
    'cisco','fortinet','fortios','fortigate','forticlient','juniper',
    'paloalto','checkpoint','sonicwall','watchguard','barracuda',
    'f5','bigip','netscaler','citrix','pulse','ivanti','globalprotect',
    'sslvpn','openvpn','wireguard','aruba','ubiquiti',
    // Infrastructure / Cloud
    'vmware','esxi','vsphere','vcenter','workstation','horizon',
    'kubernetes','docker','containerd','gitlab','jenkins','github',
    'terraform','ansible','saltstack',
    // Serveurs / Middleware
    'openssl','openssh','apache','nginx','iis','tomcat','spring','log4j',
    'log4shell','struts','weblogic','websphere','jboss','wildfly',
    // OS / Kernel
    'linux','kernel','ubuntu','debian','centos','rhel','fedora','suse',
    'freebsd','openbsd','chromeos',
    // CMS / Dev
    'wordpress','drupal','joomla','magento','woocommerce','prestashop',
    'nodejs','python','ruby','php','java','npm','pypi','rubygems','composer',
    'maven','gradle',
    // Bases de données
    'oracle','mysql','mssql','postgresql','mongodb','redis','elasticsearch',
    // Entreprise
    'sap','salesforce','servicenow','confluence','jira','atlassian',
    'zoom','slack','webex',
    // Hardware
    'intel','amd','arm','qualcomm','snapdragon','dell','hp','lenovo','ibm',
    'hikvision','dahua','zyxel','netgear','dlink','tplink',
    // Autres
    'adobe','acrobat','reader','coldfusion','flash',
  ]);

  // Noms d'entreprises (= vendor de haut niveau, pas un produit spécifique)
  const COMPANY_NAMES = new Set([
    'microsoft','google','apple','amazon','meta','cisco','fortinet','juniper',
    'paloalto','checkpoint','sonicwall','watchguard','barracuda','f5','citrix',
    'ivanti','vmware','oracle','ibm','hp','dell','lenovo','intel','amd','arm',
    'qualcomm','adobe','atlassian','sap','salesforce','servicenow',
  ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. NORMALISATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * normalizeTitle(title) → string
   *
   * • Minuscules
   * • Suppression diacritiques (NFD)
   * • Normalisation de variantes composées (zero-day → 0day, etc.)
   * • Suppression ponctuation (garde les tirets dans les CVE IDs)
   * • Normalisation des espaces
   */
  function normalizeTitle(title) {
    if (!title) return '';

    return title
      .toLowerCase()
      // 1. Suppression diacritiques
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      // 2. Normaliser variantes composées → forme canonique unique
      .replace(/zero[\s\-]?day|0[\s\-]day/g,    '0day')
      .replace(/out[\s\-]?of[\s\-]?band/g,       'outofband')
      .replace(/supply[\s\-]?chain/g,             'supplychain')
      .replace(/in[\s\-]the[\s\-]wild/g,          'inthewild')
      .replace(/man[\s\-]in[\s\-]the[\s\-]middle/g,'mitm')
      .replace(/denial[\s\-]of[\s\-]service/g,   'dos')
      .replace(/remote[\s\-]code[\s\-]execution/g,'rce')
      .replace(/privilege[\s\-]escalation/g,      'privesc')
      .replace(/proof[\s\-]of[\s\-]concept/g,     'poc')
      .replace(/authentication[\s\-]bypass/g,     'authbypass')
      // 3. Supprimer ponctuation (conserver tirets dans CVE-XXXX-XXXX)
      .replace(/[^\w\s\-]/g, ' ')
      // 4. Normaliser espaces
      .replace(/\s+/g, ' ')
      .trim();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. TOKENISATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * tokenizeTitle(normalizedTitle) → Set<string>
   *
   * Règles de conservation par ordre de priorité :
   *   1. CVE IDs         → toujours
   *   2. Termes sécu     → toujours (même si courts)
   *   3. Vendeurs/produits → toujours
   *   4. Tokens longs non-stop, non-numériques → conservés
   */
  function tokenizeTitle(normalizedTitle) {
    const tokens = new Set();

    for (const word of normalizedTitle.split(/\s+/)) {
      if (!word) continue;

      // CVE IDs  → priorité absolue
      if (/^cve-\d{4}-\d{4,}$/.test(word)) { tokens.add(word); continue; }

      // Termes sécurité → toujours
      if (SECURITY_TERMS.has(word))         { tokens.add(word); continue; }

      // Vendeurs / produits → toujours
      if (VENDORS.has(word))                { tokens.add(word); continue; }

      // Filtres généraux
      if (STOP_WORDS.has(word))  continue;
      if (word.length < 3)       continue;
      if (/^\d+$/.test(word))    continue;   // chiffres seuls

      tokens.add(word);
    }

    return tokens;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. SIMILARITÉ JACCARD
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * jaccardSimilarity(a, b) → float [0, 1]
   *
   * Accepte soit deux Set<string> (tokens pré-calculés, plus rapide)
   * soit deux chaînes (normalisées ou brutes)
   */
  function jaccardSimilarity(a, b) {
    const setA = a instanceof Set ? a : tokenizeTitle(normalizeTitle(String(a || '')));
    const setB = b instanceof Set ? b : tokenizeTitle(normalizeTitle(String(b || '')));

    if (!setA.size && !setB.size) return 1;
    if (!setA.size || !setB.size) return 0;

    let inter = 0;
    for (const t of setA) { if (setB.has(t)) inter++; }
    const union = setA.size + setB.size - inter;
    return inter / union;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. HELPERS — SIGNAUX D'ENTITÉ
  // ═══════════════════════════════════════════════════════════════════════════

  function _cveSet(article) {
    return new Set((article.cves || []).map(c => c.toUpperCase()));
  }

  /** true si au moins une CVE en commun, false si CVEs différentes, null si l'un n'a pas de CVE */
  function _sameCVESignal(a, b) {
    const ca = _cveSet(a);
    const cb = _cveSet(b);
    if (!ca.size || !cb.size) return null;
    for (const c of ca) { if (cb.has(c)) return true; }
    return false;
  }

  /** true si CVEs explicitement en conflit (les deux ont des CVEs mais aucune en commun) */
  function _conflictingCVEs(a, b) {
    const ca = _cveSet(a);
    const cb = _cveSet(b);
    if (!ca.size || !cb.size) return false;
    for (const c of ca) { if (cb.has(c)) return false; }
    return true;
  }

  function _vendorsIn(norm) {
    return new Set(norm.split(/\s+/).filter(w => VENDORS.has(w)));
  }

  function _productsIn(norm) {
    // Produit = token dans VENDORS mais PAS nom d'entreprise générique
    return new Set(norm.split(/\s+/).filter(w => VENDORS.has(w) && !COMPANY_NAMES.has(w)));
  }

  /** true | false | null (null = indéterminé, l'un des deux n'a pas de vendor connu) */
  function _sameVendorSignal(normA, normB) {
    const va = _vendorsIn(normA);
    const vb = _vendorsIn(normB);
    if (!va.size || !vb.size) return null;
    for (const v of va) { if (vb.has(v)) return true; }
    return false;
  }

  function _sameProductSignal(normA, normB) {
    const pa = _productsIn(normA);
    const pb = _productsIn(normB);
    if (!pa.size || !pb.size) return null;
    for (const p of pa) { if (pb.has(p)) return true; }
    return false;
  }

  function _canonicalURL(url) {
    try {
      const u = new URL(url);
      ['utm_source','utm_medium','utm_campaign','utm_content','utm_term',
       'ref','source','from','via','fbclid'].forEach(p => u.searchParams.delete(p));
      u.hash = '';
      return u.hostname.replace(/^www\./, '') + u.pathname.replace(/\/$/, '');
    } catch { return url || ''; }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. COMPARAISON COMPLÈTE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * compareArticles(articleA, articleB) → objet de comparaison
   *
   * {
   *   score: float,              // similarité Jaccard [0–1]
   *   normalizedTitleA: string,
   *   normalizedTitleB: string,
   *   tokensA: string[],
   *   tokensB: string[],
   *   sameCve: bool|null,        // null = l'un des deux n'a pas de CVE
   *   conflictingCVEs: bool,     // les deux ont des CVEs mais différentes
   *   sameVendor: bool|null,
   *   sameProduct: bool|null,
   *   closeInTime: bool|null,
   *   sameURL: bool,
   *   sameNormHash: bool,
   *   decision: "duplicate"|"related"|"distinct",
   *   reason: string
   * }
   */
  function compareArticles(a, b) {
    const normA  = normalizeTitle(a.title);
    const normB  = normalizeTitle(b.title);
    const tokA   = tokenizeTitle(normA);
    const tokB   = tokenizeTitle(normB);
    const score  = jaccardSimilarity(tokA, tokB);

    const sameCve        = _sameCVESignal(a, b);
    const conflictingCVEs = _conflictingCVEs(a, b);
    const sameVendor     = _sameVendorSignal(normA, normB);
    const sameProduct    = _sameProductSignal(normA, normB);

    const msA = a.pubDate instanceof Date ? a.pubDate.getTime() : 0;
    const msB = b.pubDate instanceof Date ? b.pubDate.getTime() : 0;
    const closeInTime = (msA && msB)
      ? Math.abs(msA - msB) <= CONFIG.CLOSE_IN_TIME_MS
      : null;

    const sameURL      = !!(a.link && b.link && _canonicalURL(a.link) === _canonicalURL(b.link) && a.link !== '');
    const sameNormHash = normA.length > 0 && normA === normB;

    const { decision, reason } = classifyDuplicate(
      { score, sameCve, conflictingCVEs, sameVendor, sameProduct, closeInTime, sameURL, sameNormHash }
    );

    return {
      score:            Math.round(score * 100) / 100,
      normalizedTitleA: normA,
      normalizedTitleB: normB,
      tokensA:          [...tokA],
      tokensB:          [...tokB],
      sameCve,
      conflictingCVEs,
      sameVendor,
      sameProduct,
      closeInTime,
      sameURL,
      sameNormHash,
      decision,
      reason
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. CLASSIFICATION — RÈGLES MÉTIER
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * classifyDuplicate(signals) → { decision, reason }
   *
   * Règles par priorité décroissante :
   *
   * ── DUPLICATE ──────────────────────────────────────────────────────────────
   *  R1. Même URL canonique
   *  R2. Même titre normalisé (hash exact)
   *  R3. Même CVE + même vendor/produit + Jaccard ≥ RELATED
   *       → deux couvertures du même patch sur le même produit
   *  R4. Jaccard ≥ DUPLICATE + pas de produits en conflit
   *       → reformulations du même article
   *
   * ── RELATED ────────────────────────────────────────────────────────────────
   *  R5. Même CVE + Jaccard < RELATED
   *       → étapes différentes d'un incident (advisory → PoC → KEV → patch)
   *  R6. Jaccard ≥ RELATED + au moins une entité en commun + pas de conflit CVE
   *
   * ── GARDE-FOUS (évitent les faux positifs) ─────────────────────────────────
   *  G1. CVEs explicitement en conflit → jamais DUPLICATE
   *  G2. Produits explicitement différents → jamais DUPLICATE
   *  G3. Jaccard seul insuffisant sans correspondance d'entité
   */
  function classifyDuplicate({ score, sameCve, conflictingCVEs,
                               sameVendor, sameProduct, closeInTime,
                               sameURL, sameNormHash }) {
    const { DUPLICATE, RELATED } = CONFIG.THRESHOLDS;

    // R1 — Doublon strict : même URL
    if (sameURL && sameURL !== false)
      return { decision: 'duplicate', reason: 'same-url' };

    // R2 — Doublon strict : même titre normalisé
    if (sameNormHash)
      return { decision: 'duplicate', reason: 'same-normalized-title' };

    // G1 — CVEs explicitement en conflit : pas de fusion automatique
    if (conflictingCVEs && score < DUPLICATE)
      return { decision: 'distinct', reason: 'conflicting-cves' };

    // R3 — Même CVE + même entité + similarité suffisante
    if (sameCve === true && score >= RELATED) {
      if (sameProduct === true)
        return { decision: 'duplicate', reason: 'same-cve-same-product-high-jaccard' };
      if (sameVendor === true)
        return { decision: 'duplicate', reason: 'same-cve-same-vendor-high-jaccard' };
      // Même CVE + similarité élevée sans entité identifiée
      return { decision: 'duplicate', reason: 'same-cve-high-jaccard' };
    }

    // R5 — Même CVE, titres différents → étapes d'un incident, pas un doublon
    if (sameCve === true && score < RELATED)
      return { decision: 'related', reason: 'same-cve-distinct-title' };

    // R4 — Très haute similarité
    if (score >= DUPLICATE) {
      // G2 : produits explicitement différents → refuser la fusion
      if (sameProduct === false)
        return { decision: 'related', reason: 'high-jaccard-different-products' };
      // G1 étendu : pas de fusion si CVEs en conflit (déjà géré mais double-garde)
      if (conflictingCVEs)
        return { decision: 'related', reason: 'high-jaccard-conflicting-cves' };
      // Fusion autorisée
      return { decision: 'duplicate', reason: 'high-jaccard-same-entity' };
    }

    // R6 — Similarité modérée + correspondance d'entité
    if (score >= RELATED) {
      const hasEntityMatch = sameVendor === true || sameProduct === true || sameCve === true;
      if (!hasEntityMatch)
        return { decision: 'distinct', reason: 'moderate-jaccard-no-entity-match' };
      if (conflictingCVEs)
        return { decision: 'distinct', reason: 'moderate-jaccard-conflicting-cves' };
      if (sameProduct === false && sameVendor === false)
        return { decision: 'distinct', reason: 'moderate-jaccard-different-entities' };
      // Incident lié : même entité mais couverture différente
      const timeInfo = closeInTime === false ? '-distant-in-time' : '';
      return { decision: 'related', reason: `moderate-jaccard-same-entity${timeInfo}` };
    }

    // Par défaut : articles distincts
    return { decision: 'distinct', reason: 'low-similarity-or-different-entities' };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. PIPELINE — deduplicate(articles)
  // ═══════════════════════════════════════════════════════════════════════════

  function deduplicate(articles) {
    const absorbed = new Set();  // IDs supprimés de la liste principale
    const linked   = new Map();  // articleId → Set d'IDs d'articles liés

    // Pré-calcul des formes normalisées (évite les recalculs en O(n²))
    const cache = new Map();
    for (const a of articles) {
      const norm = normalizeTitle(a.title);
      cache.set(a.id, { norm, tokens: tokenizeTitle(norm) });
    }

    for (let i = 0; i < articles.length; i++) {
      if (absorbed.has(articles[i].id)) continue;
      const primary = articles[i];
      const cA      = cache.get(primary.id);

      for (let j = i + 1; j < articles.length; j++) {
        if (absorbed.has(articles[j].id)) continue;
        const candidate = articles[j];
        const cB        = cache.get(candidate.id);

        // Score Jaccard rapide sur tokens pré-calculés
        const score = jaccardSimilarity(cA.tokens, cB.tokens);

        // Court-circuit : distinct évident (même en RELATED = 0.65, score < 0.50 → skip)
        if (score < 0.45 && !_hasCVEOverlap(primary, candidate)) continue;

        // Calcul complet des signaux
        const sameCve         = _sameCVESignal(primary, candidate);
        const conflictingCVEs = _conflictingCVEs(primary, candidate);
        const sameVendor      = _sameVendorSignal(cA.norm, cB.norm);
        const sameProduct     = _sameProductSignal(cA.norm, cB.norm);
        const sameURL         = !!(primary.link && candidate.link &&
          _canonicalURL(primary.link) === _canonicalURL(candidate.link) &&
          primary.link !== '');
        const sameNormHash    = cA.norm.length > 0 && cA.norm === cB.norm;

        const msA = primary.pubDate instanceof Date ? primary.pubDate.getTime() : 0;
        const msB = candidate.pubDate instanceof Date ? candidate.pubDate.getTime() : 0;
        const closeInTime = (msA && msB)
          ? Math.abs(msA - msB) <= CONFIG.CLOSE_IN_TIME_MS
          : null;

        const { decision, reason } = classifyDuplicate({
          score, sameCve, conflictingCVEs, sameVendor, sameProduct,
          closeInTime, sameURL, sameNormHash
        });

        if (decision === 'duplicate') {
          // Garder l'article le plus récent comme principal
          const [keep, dup] =
            (primary.pubDate || 0) >= (candidate.pubDate || 0)
              ? [primary, candidate]
              : [candidate, primary];

          keep.relatedSources = keep.relatedSources || [];
          if (!keep.relatedSources.find(s => s.sourceId === dup.source)) {
            keep.relatedSources.push({
              sourceId:   dup.source,
              sourceName: dup.sourceName,
              sourceIcon: dup.sourceIcon || '',
              link:       dup.link,
              pubDate:    dup.pubDate,
              similarity: Math.round(score * 100),
              reason
            });
          }
          absorbed.add(dup.id);

        } else if (decision === 'related') {
          // Ne pas absorber, marquer comme liés (même incident, étapes différentes)
          if (!linked.has(primary.id))   linked.set(primary.id,   new Set());
          if (!linked.has(candidate.id)) linked.set(candidate.id, new Set());
          linked.get(primary.id).add(candidate.id);
          linked.get(candidate.id).add(primary.id);
        }
      }
    }

    // Résultat : filtrer les absorbés + enrichir avec métadonnées
    const result = articles
      .filter(a => !absorbed.has(a.id))
      .map(a => ({
        ...a,
        sourceCount:     1 + (a.relatedSources?.length || 0),
        relatedSources:  a.relatedSources || [],
        relatedArticles: linked.has(a.id)
          ? [...linked.get(a.id)].filter(id => !absorbed.has(id))
          : []
      }));

    // Log de synthèse
    const nDup     = articles.length - result.length;
    const nRelated = result.filter(a => a.relatedArticles.length > 0).length;
    if (nDup > 0 || nRelated > 0) {
      console.log(
        `[Deduplicator] ${nDup} doublon(s) fusionné(s) · ` +
        `${nRelated} article(s) avec incidents liés → ` +
        `${result.length} articles uniques`
      );
    }

    return result;
  }

  // Helper interne : vérifier rapidement si CVE overlap (court-circuit en boucle)
  function _hasCVEOverlap(a, b) {
    const ca = a.cves;
    const cb = b.cves;
    if (!ca?.length || !cb?.length) return false;
    return ca.some(c => cb.includes(c));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. TESTS UNITAIRES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Deduplicator.runTests()
   * Loggue les résultats dans la console. Utile pour valider les seuils.
   */
  function runTests() {
    const now = new Date();
    const _art = (id, title, cves = [], link = null) => ({
      id, title, cves,
      pubDate:    now,
      link:       link || `https://example.com/${id}`,
      source:     `src-${id}`,
      sourceName: `Source-${id}`
    });

    const TESTS = [
      // ── Doublons attendus ──────────────────────────────────────────────────
      {
        a: _art('t1a', 'Fortinet warns of critical FortiOS vulnerability'),
        b: _art('t1b', 'Critical FortiOS flaw disclosed by Fortinet'),
        expected: 'duplicate',
        desc: 'Même story Fortinet/FortiOS, verbes/noms synonymes différents'
      },
      {
        a: _art('t2a', 'Microsoft fixes actively exploited zero-day in Windows'),
        b: _art('t2b', 'Windows zero-day exploited in the wild patched by Microsoft'),
        expected: 'duplicate',
        desc: 'Même patch Microsoft Windows zero-day, formulation inversée'
      },
      {
        a: _art('t3a', 'CVE-2025-1234 remote code execution in Apache Tomcat',
                ['CVE-2025-1234']),
        b: _art('t3b', 'Apache Tomcat RCE vulnerability CVE-2025-1234 — critical patch',
                ['CVE-2025-1234']),
        expected: 'duplicate',
        desc: 'Même CVE + même produit + haute similarité'
      },
      // ── Liés mais distincts (même incident, étapes différentes) ─────────
      {
        a: _art('t4a', 'Fortinet releases advisory for CVE-2026-1234', ['CVE-2026-1234']),
        b: _art('t4b', 'PoC published for CVE-2026-1234',              ['CVE-2026-1234']),
        expected: 'related',
        desc: 'Même CVE : advisory → PoC (étapes différentes, ne pas fusionner)'
      },
      {
        a: _art('t5a', 'CISA adds CVE-2026-1234 to KEV',              ['CVE-2026-1234']),
        b: _art('t5b', 'Fortinet releases advisory for CVE-2026-1234', ['CVE-2026-1234']),
        expected: 'related',
        desc: 'Même CVE : ajout KEV vs advisory initial'
      },
      // ── Articles distincts ─────────────────────────────────────────────────
      {
        a: _art('t6a', 'Microsoft patches CVE-2026-1000 in Exchange',  ['CVE-2026-1000']),
        b: _art('t6b', 'Microsoft fixes CVE-2026-9999 in Windows',     ['CVE-2026-9999']),
        expected: 'distinct',
        desc: 'Même vendor, CVEs différentes, produits différents'
      },
      {
        a: _art('t7a', 'Apache Log4j remote code execution vulnerability'),
        b: _art('t7b', 'Apache HTTP Server authentication bypass'),
        expected: 'distinct',
        desc: 'Même vendor Apache, produits très différents (Log4j vs HTTP Server)'
      },
      {
        a: _art('t8a', 'Google Chrome zero-day exploited in phishing campaign'),
        b: _art('t8b', 'Google Android critical vulnerability patched'),
        expected: 'distinct',
        desc: 'Même vendor Google, produits différents (Chrome vs Android)'
      },
      {
        a: _art('t9a', 'Cisco IOS XE authentication bypass CVE-2026-0001', ['CVE-2026-0001']),
        b: _art('t9b', 'Cisco ASA remote code execution CVE-2026-9999',    ['CVE-2026-9999']),
        expected: 'distinct',
        desc: 'Même vendor Cisco, produits différents (IOS XE vs ASA), CVEs différentes'
      }
    ];

    let pass = 0;
    const rows = [];

    TESTS.forEach(t => {
      const r  = compareArticles(t.a, t.b);
      const ok = r.decision === t.expected;
      if (ok) pass++;
      rows.push({
        ok,
        desc:     t.desc,
        expected: t.expected,
        got:      r.decision,
        reason:   r.reason,
        jaccard:  r.score.toFixed(2),
        cve:      r.sameCve,
        vendor:   r.sameVendor,
        product:  r.sameProduct
      });
    });

    console.group(`[Deduplicator] Tests — ${pass}/${TESTS.length} ✅`);
    rows.forEach(r =>
      console.log(
        `${r.ok ? '✅' : '❌'} [exp:${r.expected.padEnd(9)} got:${r.got.padEnd(9)}] ` +
        `J=${r.jaccard} cve=${String(r.cve).padEnd(5)} vendor=${String(r.vendor).padEnd(5)} ` +
        `prod=${String(r.product).padEnd(5)} → ${r.reason}\n   ${r.desc}`
      )
    );
    console.groupEnd();

    return { pass, fail: TESTS.length - pass, total: TESTS.length };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // API publique
  // ═══════════════════════════════════════════════════════════════════════════

  return {
    // Pipeline
    deduplicate,
    // Fonctions exposées (tests, intégration externe)
    normalizeTitle,
    tokenizeTitle,
    jaccardSimilarity,
    compareArticles,
    classifyDuplicate,
    runTests,
    // Config modifiable
    CONFIG
  };
})();
