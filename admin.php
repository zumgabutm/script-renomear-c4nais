<?php
session_start();
header('Content-Type: text/html; charset=utf-8');

@set_time_limit(0);
@ini_set("max_execution_time", "0");
@ini_set("memory_limit", "-1");

/* =========================
   CONFIG ADMIN LOCAL
========================= */
define("ADMIN_USER", "admin");
define("ADMIN_PIN",  "123poli123");

/* =========================
   PASTAS/ARQUIVOS
========================= */
$base_dir     = __DIR__;
$dados_dir    = $base_dir . "/dados";
$uploads_dir  = $base_dir . "/uploads";
$users_bk_dir = $uploads_dir . "/users";

$arquivo_users = $dados_dir . "/usuarios.json";
$arquivo_log   = $dados_dir . "/lista.json";

if (!is_dir($dados_dir))    @mkdir($dados_dir, 0777, true);
if (!is_dir($uploads_dir))  @mkdir($uploads_dir, 0777, true);
if (!is_dir($users_bk_dir)) @mkdir($users_bk_dir, 0777, true);

if (!file_exists($arquivo_users)) file_put_contents($arquivo_users, "{}");
if (!file_exists($arquivo_log))   file_put_contents($arquivo_log, "[]");

/* =========================
   FUNÇÕES BASE
========================= */
function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, "UTF-8"); }

function ler_json($arquivo, $default){
    if (!file_exists($arquivo)) return $default;
    $raw = @file_get_contents($arquivo);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}
function salvar_json($arquivo, $data){
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    file_put_contents($arquivo, $json, LOCK_EX);
}
function carregar_usuarios(){
    global $arquivo_users;
    return ler_json($arquivo_users, []);
}
function salvar_usuarios($usuarios){
    global $arquivo_users;
    salvar_json($arquivo_users, $usuarios);
}

function log_admin($acao, $detalhes = []){
    global $arquivo_log;

    $lista = ler_json($arquivo_log, []);
    $lista[] = [
        "time" => date("Y-m-d H:i:s"),
        "ts"   => time(),
        "user" => "admin",
        "ip"   => $_SERVER["REMOTE_ADDR"] ?? "",
        "ua"   => $_SERVER["HTTP_USER_AGENT"] ?? "",
        "acao" => $acao,
        "detalhes" => $detalhes
    ];
    if (count($lista) > 5000) $lista = array_slice($lista, -5000);
    salvar_json($arquivo_log, $lista);
}

function safe_join($base, $path){
    // monta caminho e garante que está dentro do base
    $full = realpath($base . "/" . ltrim($path, "/\\"));
    $baseReal = realpath($base);
    if (!$full || !$baseReal) return false;
    if (strpos($full, $baseReal) !== 0) return false;
    return $full;
}

/* =========================
   LOGIN LOCAL DO ADMIN
========================= */
$erro = "";
$msg  = "";

if (isset($_GET["logout"])) {
    unset($_SESSION["admin_ok"]);
    header("Location: admin.php");
    exit;
}

if (isset($_POST["admin_login"])) {
    $u = trim($_POST["usuario"] ?? "");
    $p = trim($_POST["pin"] ?? "");

    if ($u === ADMIN_USER && $p === ADMIN_PIN) {
        $_SESSION["admin_ok"] = true;
        log_admin("admin_login_ok");
        header("Location: admin.php");
        exit;
    } else {
        $erro = "Usuário ou PIN do admin inválido.";
        log_admin("admin_login_fail", ["usuario" => $u]);
    }
}

$admin_ok = !empty($_SESSION["admin_ok"]);

/* =========================
   DOWNLOADS (SÓ ADMIN)
========================= */
if ($admin_ok && isset($_GET["download_userfile"])) {
    $rel = (string)($_GET["download_userfile"] ?? "");
    // esperado: USUARIO/arquivo.m3u
    $path = safe_join($users_bk_dir, $rel);
    if (!$path || !file_exists($path) || !is_file($path)) {
        http_response_code(404);
        exit("Arquivo não encontrado.");
    }

    $nome = basename($path);
    log_admin("admin_download_userfile", ["file" => $rel, "bytes" => filesize($path)]);

    header("Content-Type: application/octet-stream");
    header('Content-Disposition: attachment; filename="'.$nome.'"');
    header("Content-Length: " . filesize($path));
    readfile($path);
    exit;
}

if ($admin_ok && isset($_GET["download_userzip"])) {
    $user = preg_replace('/[^a-zA-Z0-9_-]+/', '_', (string)($_GET["download_userzip"] ?? ""));
    if ($user === "") { http_response_code(400); exit("Usuário inválido."); }

    $udir = safe_join($users_bk_dir, $user);
    if (!$udir || !is_dir($udir)) { http_response_code(404); exit("Pasta do usuário não encontrada."); }

    if (!class_exists("ZipArchive")) {
        http_response_code(500);
        exit("ZipArchive não está disponível no PHP deste servidor.");
    }

    $zipPath = $base_dir . "/uploads/_admin_export_" . $user . "_" . date("Ymd_His") . ".zip";

    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE) !== true) {
        http_response_code(500);
        exit("Falha ao criar ZIP.");
    }

    $files = glob($udir . "/*.m3u");
    foreach ($files as $f) {
        if (is_file($f)) {
            $zip->addFile($f, $user . "/" . basename($f));
        }
    }
    $zip->close();

    if (!file_exists($zipPath)) { http_response_code(500); exit("Falha ao gerar ZIP."); }

    log_admin("admin_download_userzip", ["user" => $user, "zip" => basename($zipPath), "files" => count($files)]);

    header("Content-Type: application/zip");
    header('Content-Disposition: attachment; filename="'.basename($zipPath).'"');
    header("Content-Length: " . filesize($zipPath));
    readfile($zipPath);

    // opcional: apagar depois de baixar
    @unlink($zipPath);
    exit;
}

if ($admin_ok && isset($_GET["download_logs_json"])) {
    if (!file_exists($arquivo_log)) { http_response_code(404); exit("Sem logs."); }
    log_admin("admin_download_logs_json", ["bytes" => filesize($arquivo_log)]);
    header("Content-Type: application/json; charset=utf-8");
    header('Content-Disposition: attachment; filename="lista.json"');
    readfile($arquivo_log);
    exit;
}

/* =========================
   SE NÃO LOGADO: TELA LOGIN
========================= */
if (!$admin_ok) {
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>usuario</title>
<link rel="stylesheet" href="index.css">
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="dot"></div>
      <div>
        <div class="title">users</div>
        <div class="sub">passwordd</div>
      </div>
    </div>
  </div>

  <div class="grid one">
    <div class="card">
      <h3>🔐 Login</h3>

      <?php if ($erro): ?>
        <div class="msg err"><?= h($erro) ?></div>
      <?php endif; ?>

      <form method="POST" class="form">
        <label>Usuário</label>
        <input name="usuario" required placeholder="admin">

        <label>PIN</label>
        <input name="pin" required placeholder="198419" type="password">

        <button class="btn primary" type="submit" name="admin_login" value="1">✅ Entrar</button>
      </form>

      <div class="hint">
        Este login é independente do login dos alunos.
      </div>
    </div>
  </div>
</div>
</body>
</html>
<?php
exit;
}

/* =========================
   ADMIN: DADOS + AÇÕES
========================= */
$usuarios = carregar_usuarios();
$logs = ler_json($arquivo_log, []);

/* criar/editar usuário */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["salvar_user"])) {
    $u = trim($_POST["usuario"] ?? "");
    $pin = trim($_POST["pin"] ?? "");
    $exp = trim($_POST["expiracao"] ?? "");

    if ($u === "" || $pin === "" || $exp === "") {
        $msg = "Preencha usuário, PIN e expiração.";
    } else {
        $usuarios[$u] = $usuarios[$u] ?? [];
        $usuarios[$u]["pin"] = $pin;
        $usuarios[$u]["expiracao"] = $exp;

        // força relogar (sessão única)
        $usuarios[$u]["session_token"] = "";
        $usuarios[$u]["last_activity"] = $usuarios[$u]["last_activity"] ?? 0;
        $usuarios[$u]["last_ip"] = $usuarios[$u]["last_ip"] ?? "";
        $usuarios[$u]["last_ua"] = $usuarios[$u]["last_ua"] ?? "";

        salvar_usuarios($usuarios);
        log_admin("admin_salvou_usuario", ["usuario" => $u, "expiracao" => $exp]);
        $msg = "✅ Usuário salvo: $u";
    }
}

/* apagar usuário */
if (isset($_GET["del"])) {
    $del = trim($_GET["del"]);
    if ($del !== "" && $del !== "admin" && isset($usuarios[$del])) {
        unset($usuarios[$del]);
        salvar_usuarios($usuarios);
        log_admin("admin_removeu_usuario", ["usuario" => $del]);
        header("Location: admin.php?tab=usuarios");
        exit;
    }
}

/* limpar logs */
if (isset($_GET["clearlogs"]) && $_GET["clearlogs"] === "1") {
    salvar_json($arquivo_log, []);
    log_admin("admin_limpou_logs");
    header("Location: admin.php?tab=logs");
    exit;
}

/* =========================
   RESULTADOS DOS ALUNOS (arquivos)
========================= */
function listar_arquivos_do_aluno($userDir) {
    $lista = [];
    $files = glob($userDir . "/*.m3u");
    foreach ($files as $f) {
        if (!is_file($f)) continue;
        $lista[] = [
            "name" => basename($f),
            "size" => filesize($f),
            "mtime" => filemtime($f),
            "path" => $f
        ];
    }
    // mais novos primeiro
    usort($lista, fn($a,$b) => $b["mtime"] <=> $a["mtime"]);
    return $lista;
}

$alunos_files = [];
$userDirs = glob($users_bk_dir . "/*", GLOB_ONLYDIR);
foreach ($userDirs as $udir) {
    $u = basename($udir);
    $alunos_files[$u] = listar_arquivos_do_aluno($udir);
}

/* =========================
   FILTRO DE LOGS
========================= */
$f_user = trim($_GET["f_user"] ?? "");
$f_acao = trim($_GET["f_acao"] ?? "");
$logs_filtrados = array_reverse($logs);

if ($f_user !== "") {
    $logs_filtrados = array_values(array_filter($logs_filtrados, function($e) use ($f_user){
        return ($e["user"] ?? "") === $f_user;
    }));
}
if ($f_acao !== "") {
    $logs_filtrados = array_values(array_filter($logs_filtrados, function($e) use ($f_acao){
        return stripos((string)($e["acao"] ?? ""), $f_acao) !== false;
    }));
}

$tab = $_GET["tab"] ?? "dashboard";

/* =========================
   DASH COUNTS
========================= */
$totalUsers = count($usuarios);
$onlineNow = 0;
$agora = time();
foreach ($usuarios as $u => $info) {
    $la = (int)($info["last_activity"] ?? 0);
    if ($la > 0 && ($agora - $la) <= 120) $onlineNow++;
}
$scansTotais = 0;
foreach ($logs as $e) {
    if (($e["acao"] ?? "") === "renomear") $scansTotais++;
}
$zipsGerados = 0;
foreach ($logs as $e) {
    if (($e["acao"] ?? "") === "admin_download_userzip") $zipsGerados++;
}
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>lookt</title>
<link rel="stylesheet" href="index.css">
</head>
<body>
<div class="wrap">

  <div class="top">
    <div class="brand">
      <div class="dot"></div>
      <div>
        <div class="title">Admin — Dados reais (dados)</div>
        <div class="sub">Usuários • Resultados dos alunos • Logs</div>
      </div>
    </div>
    <div class="right">
      <a class="btn ghost" href="index.php">⬅️ Voltar</a>
      <a class="btn ghost" href="admin.php?logout=1">🚪 Sair do Admin</a>
    </div>
  </div>

  <?php if ($msg): ?>
    <div class="msg ok"><?= h($msg) ?></div>
  <?php endif; ?>

  <div class="tabs" style="display:flex; gap:10px; flex-wrap:wrap; margin:10px 0 18px;">
    <a class="btn <?= $tab==="dashboard"?"primary":"ghost" ?>" href="admin.php?tab=dashboard">Dashboard</a>
    <a class="btn <?= $tab==="usuarios"?"primary":"ghost" ?>" href="admin.php?tab=usuarios">Usuários</a>
    <a class="btn <?= $tab==="resultados"?"primary":"ghost" ?>" href="admin.php?tab=resultados">Resultados</a>
    <a class="btn <?= $tab==="logs"?"primary":"ghost" ?>" href="admin.php?tab=logs">Logs</a>
  </div>

  <?php if ($tab === "dashboard"): ?>
    <div class="grid">
      <div class="card">
        <h3>📊 Resumo</h3>
        <div class="grid" style="grid-template-columns: repeat(4, minmax(0,1fr)); gap:12px;">
          <div class="card" style="padding:14px; text-align:center;">
            <div style="font-size:28px; font-weight:800;"><?= (int)$totalUsers ?></div>
            <div class="hint">Usuários</div>
          </div>
          <div class="card" style="padding:14px; text-align:center;">
            <div style="font-size:28px; font-weight:800;"><?= (int)$onlineNow ?></div>
            <div class="hint">Online agora (2 min)</div>
          </div>
          <div class="card" style="padding:14px; text-align:center;">
            <div style="font-size:28px; font-weight:800;"><?= (int)$scansTotais ?></div>
            <div class="hint">Renomeações (logs)</div>
          </div>
          <div class="card" style="padding:14px; text-align:center;">
            <div style="font-size:28px; font-weight:800;"><?= (int)$zipsGerados ?></div>
            <div class="hint">ZIPs baixados (admin)</div>
          </div>
        </div>

        <div class="hint warn" style="margin-top:12px;">
          Resultados dos alunos ficam em: <b>uploads/users/USUARIO/</b>
        </div>
      </div>
    </div>
  <?php endif; ?>

  <?php if ($tab === "usuarios"): ?>
    <div class="grid">
      <div class="card">
        <h3>👤 Criar/Editar Usuário</h3>
        <form method="POST" class="form">
          <label>Usuário</label>
          <input name="usuario" required placeholder="ex: aluno1">

          <label>PIN</label>
          <input name="pin" required placeholder="ex: 1984">

          <label>Expiração (YYYY-MM-DD)</label>
          <input name="expiracao" required placeholder="2030-12-31">

          <button class="btn primary" type="submit" name="salvar_user" value="1">💾 Salvar</button>
        </form>

        <div class="hint warn">
          Ao salvar, o token do aluno é zerado (ele precisa relogar).
        </div>
      </div>

      <div class="card">
        <h3>📋 Usuários</h3>
        <div class="hint">Total: <b><?= (int)count($usuarios) ?></b></div>

        <div style="overflow:auto; max-height: 420px;">
          <table style="width:100%; border-collapse: collapse;">
            <tr>
              <th style="text-align:left; padding:8px;">Usuário</th>
              <th style="text-align:left; padding:8px;">PIN</th>
              <th style="text-align:left; padding:8px;">Expira</th>
              <th style="text-align:left; padding:8px;">IP</th>
              <th style="text-align:left; padding:8px;">Atividade</th>
              <th style="padding:8px;">Ação</th>
            </tr>

            <?php foreach ($usuarios as $u => $info): ?>
              <tr>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($u) ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($info["pin"] ?? "") ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($info["expiracao"] ?? "") ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($info["last_ip"] ?? "") ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);">
                  <?php
                    $la = (int)($info["last_activity"] ?? 0);
                    echo $la ? h(date("Y-m-d H:i:s", $la)) : "—";
                  ?>
                </td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08); text-align:center;">
                  <?php if ($u !== "admin"): ?>
                    <a class="btn ghost" href="admin.php?tab=usuarios&del=<?= urlencode($u) ?>" onclick="return confirm('Remover usuário?')">🗑️</a>
                  <?php else: ?>
                    —
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>

          </table>
        </div>
      </div>
    </div>
  <?php endif; ?>

  <?php if ($tab === "resultados"): ?>
    <div class="card">
      <h3>📦 Resultados dos alunos (arquivos gerados)</h3>
      <div class="hint">
        Aqui você baixa tudo que cada aluno gerou (merged/final/backups).
      </div>

      <div style="overflow:auto; max-height: 640px; margin-top:10px;">
        <table style="width:100%; border-collapse: collapse;">
          <tr>
            <th style="text-align:left; padding:8px;">Aluno</th>
            <th style="text-align:left; padding:8px;">Arquivo</th>
            <th style="text-align:left; padding:8px;">Data</th>
            <th style="text-align:left; padding:8px;">Tamanho</th>
            <th style="padding:8px; text-align:center;">Ações</th>
          </tr>

          <?php foreach ($alunos_files as $aluno => $files): ?>
            <?php if (count($files) === 0) continue; ?>
            <?php
              $zipLink = "admin.php?tab=resultados&download_userzip=" . urlencode($aluno);
            ?>
            <tr>
              <td colspan="5" style="padding:10px; border-top:1px solid rgba(255,255,255,.12); background: rgba(255,255,255,.03);">
                <b><?= h($aluno) ?></b>
                <span class="hint">• <?= (int)count($files) ?> arquivo(s)</span>
                <span style="float:right;">
                  <a class="btn ghost" href="<?= h($zipLink) ?>">🗜️ Baixar ZIP do aluno</a>
                </span>
              </td>
            </tr>

            <?php foreach ($files as $f): ?>
              <?php
                $rel = $aluno . "/" . $f["name"];
                $dl  = "admin.php?tab=resultados&download_userfile=" . urlencode($rel);
                $dt  = date("Y-m-d H:i:s", (int)$f["mtime"]);
                $sz  = number_format(((int)$f["size"]) / 1024, 1, ",", ".") . " KB";
              ?>
              <tr>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($aluno) ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($f["name"]) ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($dt) ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($sz) ?></td>
                <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08); text-align:center;">
                  <a class="btn ghost" href="<?= h($dl) ?>">⬇️ Baixar</a>
                </td>
              </tr>
            <?php endforeach; ?>

          <?php endforeach; ?>

        </table>
      </div>

      <?php if (count($alunos_files) === 0): ?>
        <div class="hint warn" style="margin-top:12px;">
          Ainda não há pastas em <b>uploads/users/</b>. (Isso aparece quando o aluno gera/renomeia e o index faz backup.)
        </div>
      <?php endif; ?>
    </div>
  <?php endif; ?>

  <?php if ($tab === "logs"): ?>
    <div class="card">
      <h3>🧾 Logs (interface)</h3>

      <form method="GET" class="form" style="margin-top:10px;">
        <input type="hidden" name="tab" value="logs">

        <label>Filtrar por usuário</label>
        <input name="f_user" placeholder="ex: rafa" value="<?= h($f_user) ?>">

        <label>Filtrar por ação (contém)</label>
        <input name="f_acao" placeholder="ex: download / renomear / merge" value="<?= h($f_acao) ?>">

        <button class="btn primary" type="submit">🔎 Filtrar</button>
        <a class="btn ghost" href="admin.php?tab=logs">Limpar filtro</a>

        <a class="btn ghost" href="admin.php?tab=logs&download_logs_json=1">⬇️ Baixar lista.json</a>
        <a class="btn ghost" href="admin.php?tab=logs&clearlogs=1" onclick="return confirm('Limpar logs?')">🧹 Limpar logs</a>
      </form>

      <div class="hint">Mostrando até <b>300</b> eventos (mais recentes primeiro).</div>

      <div style="overflow:auto; max-height: 640px; margin-top:10px;">
        <table style="width:100%; border-collapse: collapse;">
          <tr>
            <th style="text-align:left; padding:8px;">Data</th>
            <th style="text-align:left; padding:8px;">Usuário</th>
            <th style="text-align:left; padding:8px;">Ação</th>
            <th style="text-align:left; padding:8px;">Resumo</th>
            <th style="text-align:left; padding:8px;">IP</th>
          </tr>

          <?php
            $mostrar = array_slice($logs_filtrados, 0, 300);

            function resumo_evento($e){
                $acao = (string)($e["acao"] ?? "");
                $d = $e["detalhes"] ?? [];
                if (!is_array($d)) $d = [];

                if ($acao === "merge_com_nome" || $acao === "merge_puro") {
                    $c = $d["canais_total"] ?? "";
                    $a = $d["arquivos_recebidos"] ?? "";
                    $b = $d["backup"] ?? "";
                    return "canais={$c} • arquivos={$a} • backup={$b}";
                }
                if ($acao === "renomear") {
                    $p = $d["plataforma"] ?? "";
                    $c = $d["canais_total"] ?? "";
                    $b = $d["backup"] ?? "";
                    return "plataforma={$p} • canais={$c} • backup={$b}";
                }
                if ($acao === "download") {
                    $ar = $d["arquivo"] ?? "";
                    $by = $d["bytes"] ?? "";
                    return "arquivo={$ar} • bytes={$by}";
                }
                if ($acao === "admin_download_userfile") {
                    return "file=" . ($d["file"] ?? "");
                }
                if ($acao === "admin_download_userzip") {
                    return "user=" . ($d["user"] ?? "") . " • files=" . ($d["files"] ?? "");
                }
                if ($acao === "login_ok") return "login OK";
                if ($acao === "kick_session") return "derrubou sessão (token)";
                if ($acao === "session_expired") return "sessão expirada";
                return $d ? json_encode($d, JSON_UNESCAPED_UNICODE) : "—";
            }
          ?>

          <?php foreach ($mostrar as $e): ?>
            <tr>
              <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($e["time"] ?? "") ?></td>
              <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($e["user"] ?? "") ?></td>
              <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($e["acao"] ?? "") ?></td>
              <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h(resumo_evento($e)) ?></td>
              <td style="padding:8px; border-top:1px solid rgba(255,255,255,.08);"><?= h($e["ip"] ?? "") ?></td>
            </tr>
          <?php endforeach; ?>

        </table>
      </div>
    </div>
  <?php endif; ?>

  <div class="footer" style="margin-top:14px;">
    Base: <b>dados/usuarios.json</b> • Logs: <b>dados/lista.json</b> • Resultados: <b>uploads/users/</b>
  </div>

</div>
</body>
</html>
