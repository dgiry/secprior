<?php
// fetch-feeds.php — Proxy RSS pour Hostinger
// Remplace allorigins.win : fetch le flux RSS côté serveur, renvoie le XML brut
// Cache Hostinger 5 min via header Cache-Control

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$url = $_GET['url'] ?? '';

if (!$url) {
    http_response_code(400);
    header("Content-Type: application/json");
    echo json_encode(["error" => "Paramètre 'url' requis"]);
    exit;
}

// Sécurité : autoriser uniquement http/https
$parsed = parse_url($url);
if (!in_array($parsed['scheme'] ?? '', ['http', 'https'])) {
    http_response_code(400);
    header("Content-Type: application/json");
    echo json_encode(["error" => "Protocole non autorisé"]);
    exit;
}

// Fetch via cURL (plus fiable que file_get_contents sur Hostinger)
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 3,
    CURLOPT_TIMEOUT        => 10,
    CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; CyberVeille-Pro/2.0)',
    CURLOPT_HTTPHEADER     => [
        'Accept: application/rss+xml, application/atom+xml, application/xml, text/xml, */*'
    ],
    CURLOPT_SSL_VERIFYPEER => true,
]);

$body    = curl_exec($ch);
$status  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error   = curl_error($ch);
curl_close($ch);

if ($error || $body === false) {
    http_response_code(502);
    header("Content-Type: application/json");
    echo json_encode(["error" => "Erreur proxy : " . ($error ?: "réponse vide")]);
    exit;
}

if ($status >= 400) {
    http_response_code(502);
    header("Content-Type: application/json");
    echo json_encode(["error" => "Flux RSS inaccessible (HTTP $status)", "feedUrl" => $url]);
    exit;
}

// Cache 5 min côté client + CDN Hostinger si actif
header("Cache-Control: public, max-age=300, s-maxage=300");
header("Content-Type: application/xml; charset=utf-8");
echo $body;
