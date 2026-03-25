<?php
// nvd.php — Proxy NVD (NIST) pour Hostinger
// Clé API NVD lue depuis secret.php (jamais exposée au navigateur)
// Cache 24h côté client

require_once __DIR__ . '/secret.php';

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Content-Type: application/json; charset=utf-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$cveId = strtoupper(trim($_GET['cveId'] ?? ''));

if (!$cveId) {
    http_response_code(400);
    echo json_encode(["error" => "Paramètre 'cveId' requis"]);
    exit;
}

// Valider le format CVE
if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cveId)) {
    http_response_code(400);
    echo json_encode(["error" => "Format CVE invalide (attendu: CVE-YYYY-NNNNN)"]);
    exit;
}

$url     = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" . urlencode($cveId);
$headers = ['Accept: application/json'];
if (defined('NVD_API_KEY') && NVD_API_KEY !== '') {
    $headers[] = 'apiKey: ' . NVD_API_KEY;
}

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 12,
    CURLOPT_HTTPHEADER     => $headers,
    CURLOPT_SSL_VERIFYPEER => true,
]);

$body   = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error  = curl_error($ch);
curl_close($ch);

if ($error || $body === false) {
    http_response_code(502);
    echo json_encode(["error" => "Erreur NVD : " . ($error ?: "réponse vide"), "cveId" => $cveId]);
    exit;
}

if ($status !== 200) {
    http_response_code($status ?: 502);
    echo json_encode(["error" => "NVD API : HTTP $status", "cveId" => $cveId]);
    exit;
}

header("Cache-Control: public, max-age=86400"); // 24h
echo $body;
