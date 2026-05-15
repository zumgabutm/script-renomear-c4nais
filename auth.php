<?php
session_start();
header('Content-Type: text/html; charset=utf-8');

$dados_dir = __DIR__ . '/dados';
$arquivo_usuarios = $dados_dir . '/usuarios.json';
$arquivo_log = $dados_dir . '/lista.json';

if (!file_exists($dados_dir)) {
    mkdir($dados_dir, 0777, true);
}
if (!file_exists($arquivo_usuarios)) {
    file_put_contents($arquivo_usuarios, "{}");
}
if (!file_exists($arquivo_log)) {
    file_put_contents($arquivo_log, "[]");
}

function ler_json($arquivo, $default) {
    if (!file_exists($arquivo)) return $default;
    $raw = file_get_contents($arquivo);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}

function salvar_json($arquivo, $data) {
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    file_put_contents($arquivo, $json, LOCK_EX);
}

/* ==========================================================
   ✅ LOG SIMPLES (lista.json)
========================================================== */
function log_evento($acao, $detalhes = []) {
    global $arquivo_log;

    $lista = ler_json($arquivo_log, []);
    $lista[] = [
        "time" => date("Y-m-d H:i:s"),
        "ts" => time(),
        "user" => $_SESSION['usuario_logado'] ?? "visitante",
        "ip" => $_SERVER['REMOTE_ADDR'] ?? "",
        "ua" => $_SERVER['HTTP_USER_AGENT'] ?? "",
        "acao" => $acao,
        "detalhes" => $detalhes
    ];

    // mantém os últimos 5000 logs pra não crescer infinito
    if (count($lista) > 5000) {
        $lista = array_slice($lista, -5000);
    }

    salvar_json($arquivo_log, $lista);
}

/* ==========================================================
   ✅ SESSÃO ÚNICA (ANTI 2 LOGINS)
========================================================== */
function carregar_usuarios() {
    global $arquivo_usuarios;
    return ler_json($arquivo_usuarios, []);
}

function salvar_usuarios($usuarios) {
    global $arquivo_usuarios;
    salvar_json($arquivo_usuarios, $usuarios);
}

function exigir_login() {
    $usuarios = carregar_usuarios();

    if (!isset($_SESSION['usuario_logado'])) {
        header("Location: index.php");
        exit;
    }

    $u = $_SESSION['usuario_logado'];
    if (!isset($usuarios[$u])) {
        unset($_SESSION['usuario_logado'], $_SESSION['session_token']);
        header("Location: index.php");
        exit;
    }

    $exp = strtotime($usuarios[$u]['expiracao'] ?? '');
    if ($exp < time()) {
        unset($_SESSION['usuario_logado'], $_SESSION['session_token']);
        header("Location: index.php");
        exit;
    }

    $token_sessao = $_SESSION['session_token'] ?? '';
    $token_salvo  = $usuarios[$u]['session_token'] ?? '';

    if (!$token_sessao || !$token_salvo || !hash_equals($token_salvo, $token_sessao)) {
        unset($_SESSION['usuario_logado'], $_SESSION['session_token']);
        header("Location: index.php?kick=1");
        exit;
    }

    // marca atividade
    $usuarios[$u]['last_activity'] = time();
    $usuarios[$u]['last_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
    $usuarios[$u]['last_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    salvar_usuarios($usuarios);
}
