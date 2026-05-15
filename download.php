<?php
require __DIR__ . "/auth.php";
exigir_login();

$map = [
    "merged" => __DIR__ . "/uploads/merged.m3u",
    "final"  => __DIR__ . "/uploads/final.m3u",
];

$key = $_GET["f"] ?? "";
if (!isset($map[$key])) {
    http_response_code(404);
    exit("Arquivo inválido.");
}

$path = $map[$key];
if (!file_exists($path)) {
    http_response_code(404);
    exit("Arquivo não existe.");
}

$size = filesize($path);
$nome = basename($path);

// log do download
log_evento("download", [
    "arquivo" => $nome,
    "size_bytes" => $size
]);

header("Content-Type: application/octet-stream");
header('Content-Disposition: attachment; filename="'.$nome.'"');
header("Content-Length: " . $size);
readfile($path);
exit;
