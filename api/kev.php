<?php
// kev.php — Proxy CISA KEV (Known Exploited Vulnerabilities) pour Hostinger
// ~1 200 CVE exploités activement confirmés par CISA
// Cache 24h — liste mise à jour plusieurs fois par semaine

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Content-Type: application/json; charset=utf-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_USERAGENT      => 'CyberVeille-Pro/2.0',
    CURLOPT_HTTPHEADER     => ['Accept: application/json'],
    CURLOPT_SSL_VERIFYPEER => true,
]);

$body   = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error  = curl_error($ch);
curl_close($ch);

if ($error || $body === false) {
    http_response_code(502);
    echo json_encode(["error" => "Erreur CISA KEV : " . ($error ?: "réponse vide")]);
    exit;
}

if ($status !== 200) {
    http_response_code($status ?: 502);
    echo json_encode(["error" => "CISA KEV inaccessible (HTTP $status)"]);
    exit;
}

// Log debug (visible dans les logs Hostinger Error Log)
$data  = json_decode($body, true);
$count = count($data['vulnerabilities'] ?? []);
error_log("[KEV] $count vulnérabilités chargées depuis CISA");

header("Cache-Control: public, max-age=86400"); // 24h
echo $body;
