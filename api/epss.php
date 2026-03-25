<?php
// epss.php — Proxy EPSS (api.first.org) pour Hostinger
// Retourne les scores de probabilité d'exploitation par CVE
// Cache 24h — scores mis à jour 1×/jour par FIRST

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Content-Type: application/json; charset=utf-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$cves = trim($_GET['cves'] ?? '');

if (!$cves) {
    http_response_code(400);
    echo json_encode(["error" => "Paramètre 'cves' requis (liste CVE séparés par virgule)"]);
    exit;
}

// Valider et nettoyer les CVE IDs
$ids = array_filter(
    array_map('strtoupper', array_map('trim', explode(',', $cves))),
    fn($id) => preg_match('/^CVE-\d{4}-\d{4,}$/', $id)
);

if (empty($ids)) {
    http_response_code(400);
    echo json_encode(["error" => "Aucun CVE valide dans la liste"]);
    exit;
}

$url = "https://api.first.org/data/v1/epss?cve=" . implode(',', array_slice($ids, 0, 1000));

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 12,
    CURLOPT_HTTPHEADER     => ['Accept: application/json'],
    CURLOPT_SSL_VERIFYPEER => true,
]);

$body   = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error  = curl_error($ch);
curl_close($ch);

if ($error || $body === false) {
    http_response_code(502);
    echo json_encode(["error" => "Erreur EPSS : " . ($error ?: "réponse vide")]);
    exit;
}

if ($status !== 200) {
    http_response_code($status ?: 502);
    echo json_encode(["error" => "EPSS API : HTTP $status"]);
    exit;
}

header("Cache-Control: public, max-age=86400"); // 24h
echo $body;
