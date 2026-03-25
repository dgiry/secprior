<?php
// send-alert.php — Dispatcher email sécurisé pour Hostinger
// Les clés API sont lues depuis secret.php (jamais exposées au navigateur ✅)
//
// Payload POST JSON attendu :
//   { "channel": "resend"|"sendgrid", "to": "...", "subject": "...", "html": "...", "text": "..." }

require_once __DIR__ . '/secret.php';

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json; charset=utf-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["error" => "Méthode non autorisée"]);
    exit;
}

// Lire le body JSON
$raw  = file_get_contents('php://input');
$body = json_decode($raw, true);

if (!$body) {
    http_response_code(400);
    echo json_encode(["error" => "Body JSON invalide"]);
    exit;
}

$channel = $body['channel'] ?? '';
$to      = $body['to']      ?? '';
$subject = $body['subject'] ?? '';
$html    = $body['html']    ?? '';
$text    = $body['text']    ?? '';

// Validation
if (!$channel || !$to || !$subject || (!$html && !$text)) {
    http_response_code(400);
    echo json_encode(["error" => "Champs requis manquants : channel, to, subject, html/text"]);
    exit;
}

if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(["error" => "Email destinataire invalide"]);
    exit;
}

// ── Helpers cURL ──────────────────────────────────────────────────────────────

function curlPost(string $url, array $headers, string $body): array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_TIMEOUT        => 12,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $response = curl_exec($ch);
    $status   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);
    curl_close($ch);
    return ['body' => $response, 'status' => $status, 'error' => $error];
}

// ── Canal Resend ───────────────────────────────────────────────────────────────

if ($channel === 'resend') {
    $apiKey = defined('RESEND_API_KEY') ? RESEND_API_KEY : '';
    if (!$apiKey || $apiKey === 're_XXXXXXXXXXXXXXXXXXXX') {
        http_response_code(500);
        echo json_encode(["error" => "RESEND_API_KEY non configurée dans api/secret.php"]);
        exit;
    }

    $from    = $body['fromOverride'] ?? (defined('RESEND_FROM') ? RESEND_FROM : '');
    $from    = $from ?: 'CyberVeille Pro <onboarding@resend.dev>';
    $payload = json_encode([
        'from'    => $from,
        'to'      => [$to],
        'subject' => $subject,
        'html'    => $html ?: null,
        'text'    => $text ?: null,
        'tags'    => [
            ['name' => 'source',  'value' => 'cyberveille-pro'],
            ['name' => 'channel', 'value' => 'resend'],
        ],
    ]);

    $result = curlPost(
        'https://api.resend.com/emails',
        ["Authorization: Bearer $apiKey", "Content-Type: application/json"],
        $payload
    );

    if ($result['error']) {
        http_response_code(502);
        echo json_encode(["error" => "Resend : " . $result['error']]);
        exit;
    }

    $json = json_decode($result['body'], true) ?? [];
    if ($result['status'] < 200 || $result['status'] >= 300) {
        http_response_code($result['status']);
        echo json_encode(["error" => $json['message'] ?? $json['name'] ?? "Resend HTTP " . $result['status']]);
        exit;
    }

    error_log("[send-alert] Resend OK — id: " . ($json['id'] ?? '?') . ", to: $to");
    echo json_encode(["success" => true, "channel" => "resend", "id" => $json['id'] ?? null]);
    exit;
}

// ── Canal SendGrid ────────────────────────────────────────────────────────────

if ($channel === 'sendgrid') {
    $apiKey = defined('SENDGRID_API_KEY') ? SENDGRID_API_KEY : '';
    if (!$apiKey || $apiKey === 'SG.XXXXXXXXXXXXXXXXXXXX') {
        http_response_code(500);
        echo json_encode(["error" => "SENDGRID_API_KEY non configurée dans api/secret.php"]);
        exit;
    }

    $fromEmail = $body['fromOverride'] ?? (defined('SENDGRID_FROM') ? SENDGRID_FROM : '');
    if (!$fromEmail) {
        http_response_code(500);
        echo json_encode(["error" => "SENDGRID_FROM non configuré dans api/secret.php"]);
        exit;
    }

    $content = [];
    if ($text) $content[] = ['type' => 'text/plain', 'value' => $text];
    if ($html) $content[] = ['type' => 'text/html',  'value' => $html];

    $payload = json_encode([
        'personalizations' => [['to' => [['email' => $to]], 'subject' => $subject]],
        'from'             => ['email' => $fromEmail, 'name' => 'CyberVeille Pro'],
        'content'          => $content,
        'categories'       => ['cyberveille-pro'],
    ]);

    $result = curlPost(
        'https://api.sendgrid.com/v3/mail/send',
        ["Authorization: Bearer $apiKey", "Content-Type: application/json"],
        $payload
    );

    if ($result['error']) {
        http_response_code(502);
        echo json_encode(["error" => "SendGrid : " . $result['error']]);
        exit;
    }

    // SendGrid retourne 202 sans body en cas de succès
    if ($result['status'] !== 202) {
        $json = json_decode($result['body'], true) ?? [];
        $msg  = $json['errors'][0]['message'] ?? "SendGrid HTTP " . $result['status'];
        http_response_code($result['status']);
        echo json_encode(["error" => $msg]);
        exit;
    }

    error_log("[send-alert] SendGrid OK (202) — to: $to");
    echo json_encode(["success" => true, "channel" => "sendgrid"]);
    exit;
}

// Canal non supporté
http_response_code(400);
echo json_encode([
    "error" => "Canal '$channel' non supporté (webhook/emailjs/mailto gérés côté client)"
]);
