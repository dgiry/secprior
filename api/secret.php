<?php
// ─────────────────────────────────────────────────────────────────────────────
// secret.php — Clés API (jamais accessible depuis le navigateur)
// Protégé par api/.htaccess → accès HTTP bloqué
// Modifiez les valeurs ci-dessous AVANT d'uploader sur Hostinger
// ─────────────────────────────────────────────────────────────────────────────

// NVD API (optionnel) — https://nvd.nist.gov/developers/request-an-api-key
define('NVD_API_KEY', '');

// Resend — https://resend.com/api-keys
define('RESEND_API_KEY', 're_XXXXXXXXXXXXXXXXXXXX');
define('RESEND_FROM',    'CyberVeille Pro <alerts@votredomaine.com>');

// SendGrid — https://app.sendgrid.com/settings/api_keys
define('SENDGRID_API_KEY', 'SG.XXXXXXXXXXXXXXXXXXXX');
define('SENDGRID_FROM',    'alerts@votredomaine.com');
