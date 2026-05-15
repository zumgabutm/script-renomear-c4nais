<?php
session_start();
header('Content-Type: text/html; charset=utf-8');

/* =========================
   SEM LIMITES (processamento)
========================= */
@set_time_limit(0);
@ini_set("max_execution_time", "0");
@ini_set("memory_limit", "-1");

/* =========================
   PASTAS/ARQUIVOS
========================= */
$dados_dir      = __DIR__ . "/dados";
$uploads_dir    = __DIR__ . "/uploads";
$users_bk_dir   = $uploads_dir . "/users";

$arquivo_users  = $dados_dir . "/usuarios.json";
$arquivo_log    = $dados_dir . "/lista.json";

$arquivoMerged  = $uploads_dir . "/merged.m3u";
$arquivoFinal   = $uploads_dir . "/final.m3u";

if (!is_dir($dados_dir))     @mkdir($dados_dir, 0777, true);
if (!is_dir($uploads_dir))   @mkdir($uploads_dir, 0777, true);
if (!is_dir($users_bk_dir))  @mkdir($users_bk_dir, 0777, true);

if (!file_exists($arquivo_users)) file_put_contents($arquivo_users, "{}");
if (!file_exists($arquivo_log))   file_put_contents($arquivo_log, "[]");

/* =========================
   FUNÇÕES BASE (sem redeclare)
========================= */
if (!function_exists("ler_json")) {
    function ler_json($arquivo, $default) {
        if (!file_exists($arquivo)) return $default;
        $raw = @file_get_contents($arquivo);
        $data = json_decode($raw, true);
        return is_array($data) ? $data : $default;
    }
}
if (!function_exists("salvar_json")) {
    function salvar_json($arquivo, $data) {
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        file_put_contents($arquivo, $json, LOCK_EX);
    }
}
if (!function_exists("h")) {
    function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, "UTF-8"); }
}

/* =========================
   LOG (lista.json)
========================= */
function log_evento($acao, $detalhes = []) {
    global $arquivo_log;

    $lista = ler_json($arquivo_log, []);
    $lista[] = [
        "time" => date("Y-m-d H:i:s"),
        "ts"   => time(),
        "user" => $_SESSION["usuario_logado"] ?? "",
        "ip"   => $_SERVER["REMOTE_ADDR"] ?? "",
        "ua"   => $_SERVER["HTTP_USER_AGENT"] ?? "",
        "acao" => $acao,
        "detalhes" => $detalhes
    ];

    // mantém no máximo 5000 eventos
    if (count($lista) > 5000) $lista = array_slice($lista, -5000);
    salvar_json($arquivo_log, $lista);
}

/* =========================
   LOGIN (sessão única por token)
========================= */
$usuarios = ler_json($arquivo_users, []);
$logado = false;
$erro_login = "";
$usuario_atual = "";
$tempo_restante = 0;

function salvarUsuariosJson($arquivo_users, $usuarios) {
    salvar_json($arquivo_users, $usuarios);
}

/* logout */
if (isset($_GET["logout"])) {
    $u = $_SESSION["usuario_logado"] ?? "";
    unset($_SESSION["usuario_logado"], $_SESSION["session_token"]);
    if ($u) log_evento("logout", ["usuario" => $u]);
    header("Location: index.php");
    exit;
}

/* login */
if (isset($_POST["login"])) {
    $usuario = trim($_POST["usuario"] ?? "");
    $pin     = trim($_POST["pin"] ?? "");

    if ($usuario === "" || $pin === "") {
        $erro_login = "Preencha usuário e PIN.";
    } elseif (isset($usuarios[$usuario]) && ($usuarios[$usuario]["pin"] ?? "") === $pin) {
        $exp = strtotime($usuarios[$usuario]["expiracao"] ?? "");

        if ($exp && $exp >= time()) {
            $novo_token = bin2hex(random_bytes(24));

            $_SESSION["usuario_logado"] = $usuario;
            $_SESSION["session_token"]  = $novo_token;

            $usuarios[$usuario]["session_token"] = $novo_token;
            $usuarios[$usuario]["last_activity"] = time();
            $usuarios[$usuario]["last_ip"] = $_SERVER["REMOTE_ADDR"] ?? "";
            $usuarios[$usuario]["last_ua"] = $_SERVER["HTTP_USER_AGENT"] ?? "";

            salvarUsuariosJson($arquivo_users, $usuarios);
            log_evento("login_ok", ["usuario" => $usuario]);

            header("Location: index.php");
            exit;
        } else {
            $erro_login = "Conta expirada.";
        }
    } else {
        $erro_login = "Usuário ou PIN incorreto.";
    }
}

/* checa token */
if (isset($_SESSION["usuario_logado"])) {
    $u = $_SESSION["usuario_logado"];

    if (isset($usuarios[$u])) {
        $exp = strtotime($usuarios[$u]["expiracao"] ?? "");
        if ($exp && $exp >= time()) {
            $token_sessao = $_SESSION["session_token"] ?? "";
            $token_salvo  = $usuarios[$u]["session_token"] ?? "";

            if (!$token_sessao || !$token_salvo || !hash_equals($token_salvo, $token_sessao)) {
                unset($_SESSION["usuario_logado"], $_SESSION["session_token"]);
                $logado = false;
                $erro_login = "Você foi desconectado: sua conta entrou em outro dispositivo.";
                log_evento("kick_session", ["usuario" => $u]);
            } else {
                $logado = true;
                $usuario_atual = $u;
                $tempo_restante = $exp - time();

                $usuarios[$u]["last_activity"] = time();
                $usuarios[$u]["last_ip"] = $_SERVER["REMOTE_ADDR"] ?? "";
                $usuarios[$u]["last_ua"] = $_SERVER["HTTP_USER_AGENT"] ?? "";
                salvarUsuariosJson($arquivo_users, $usuarios);
            }
        } else {
            unset($_SESSION["usuario_logado"], $_SESSION["session_token"]);
            $logado = false;
            $erro_login = "Sua sessão expirou.";
            log_evento("session_expired", ["usuario" => $u]);
        }
    } else {
        unset($_SESSION["usuario_logado"], $_SESSION["session_token"]);
        $logado = false;
    }
}

/* =========================
   SE NÃO LOGADO -> TELA LOGIN
========================= */
if (!$logado) {
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login</title>
<link rel="stylesheet" href="index.css">
</head>
<body>
<div class="wrap">
    <div class="top">
        <div class="brand">
            <div class="dot"></div>
            <div>
                <div class="title">HOMBRE</div>
                <div class="sub">Login com sessão única</div>
            </div>
        </div>
    </div>

    <div class="grid one">
        <div class="card">
            <h3>🔐 Entrar</h3>

            <?php if ($erro_login): ?>
                <div class="msg err"><?= h($erro_login) ?></div>
            <?php endif; ?>

            <form method="POST" class="form">
                <label>Usuário</label>
                <input type="text" name="usuario" placeholder="ex: aluno1" required>

                <label>PIN</label>
                <input type="password" name="pin" placeholder="ex: 1234" required>

                <button class="btn primary" type="submit" name="login" value="1">✅ Entrar</button>
            </form>

            <div class="hint">
                gratis<b>proibido</b>20137<b>vendas</b>).
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
   FUNÇÕES M3U (ROBUSTAS + IP:PORT)
========================= */

/**
 * Converte linha em URL:
 * - aceita http/https
 * - aceita IP:PORT ou dominio:PORT e vira http://...
 */
function normalizar_url_linha($ln) {
    $ln = trim((string)$ln);
    if ($ln === "") return "";

    // remove BOM invisível
    $ln = preg_replace('/^\xEF\xBB\xBF/', '', $ln);

    // já é http/https
    if (preg_match('/^https?:\/\//i', $ln)) return $ln;

    // aceita IP:PORT ou domínio:PORT
    if (preg_match('/^(?:(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})(?::\d{2,5})$/i', $ln)) {
        return "http://" . $ln;
    }

    return "";
}

function parse_m3u_urls($content) {
    $lines = preg_split("/\r\n|\n|\r/", (string)$content);
    $urls = [];
    foreach ($lines as $ln) {
        $u = normalizar_url_linha($ln);
        if ($u !== "") $urls[] = $u;
    }
    return $urls;
}

/**
 * Não “come canal”:
 * - pega EXTINF
 * - procura a próxima URL (http/https ou IP:PORT) pulando tags
 */
function parse_m3u_entries($content) {
    $lines = preg_split("/\r\n|\n|\r/", (string)$content);
    $entries = [];
    $n = count($lines);

    for ($i = 0; $i < $n; $i++) {
        $line = trim($lines[$i]);

        if (stripos($line, "#EXTINF") === 0) {
            $extinf = $line;
            $url = "";

            for ($j = $i + 1; $j < $n; $j++) {
                $next = trim($lines[$j]);
                if ($next === "") continue;

                // chegou no próximo canal
                if (stripos($next, "#EXTINF") === 0) break;

                // ignora tags
                if ($next[0] === "#") continue;

                // aceita URL ou IP:PORT
                $u = normalizar_url_linha($next);
                if ($u !== "") {
                    $url = $u;
                    $i = $j; // avança o ponteiro principal até a url
                    break;
                }
            }

            if ($url !== "") $entries[] = ["extinf" => $extinf, "url" => $url];
        }
    }

    return $entries;
}

function slugify($text) {
    $text = trim((string)$text);
    $text = mb_strtolower($text, "UTF-8");
    $text = preg_replace('/[^\p{L}\p{Nd}]+/u', '-', $text);
    $text = trim($text, '-');
    return ($text === "") ? "canal" : $text;
}

function cat_icon($tipo) {
    $tipo = strtoupper(trim((string)$tipo));
    if ($tipo === "FILMES") return "🎬 FILMES";
    if ($tipo === "CANAIS") return "🔵 CANAIS";
    if ($tipo === "CANAL")  return "🟢 CANAL";
    if ($tipo === "ESPORTES") return "⚽ ESPORTES";
    return "● " . $tipo;
}

function gerar_m3u_por_nome_base($urls, $nomeBase, $logo = "", $categoria = "") {
    $out = ["#EXTM3U"];
    $total = count($urls);

    for ($i = 0; $i < $total; $i++) {
        // sem limite real: 1..500..900...
        $num = (string)($i + 1);
        $nomeFinal = $nomeBase . " " . $num;
        $tvgid = slugify($nomeFinal);

        $extinf = '#EXTINF:-1'
            . ' tvg-id="' . htmlspecialchars($tvgid, ENT_QUOTES) . '"'
            . ' tvg-name="' . htmlspecialchars($nomeFinal, ENT_QUOTES) . '"';

        if ($logo !== "") $extinf .= ' tvg-logo="' . htmlspecialchars($logo, ENT_QUOTES) . '"';
        if ($categoria !== "") $extinf .= ' group-title="' . htmlspecialchars($categoria, ENT_QUOTES) . '"';

        $extinf .= ',' . $nomeFinal;

        $out[] = $extinf;
        $out[] = $urls[$i];
    }

    return implode("\n", $out) . "\n";
}

function gerar_final_padronizado($urls, $nomeBase, $categoria, $logo, $arquivoFinal) {
    $out = ["#EXTM3U"];
    $total = count($urls);

    for ($i = 0; $i < $total; $i++) {
        $num = (string)($i + 1);
        $nomeFinal = $nomeBase . " " . $num;
        $tvgid = slugify($nomeFinal);

        $extinf = '#EXTINF:-1'
            . ' tvg-id="' . htmlspecialchars($tvgid, ENT_QUOTES) . '"'
            . ' tvg-name="' . htmlspecialchars($nomeFinal, ENT_QUOTES) . '"';

        if ($logo !== "") $extinf .= ' tvg-logo="' . htmlspecialchars($logo, ENT_QUOTES) . '"';

        $extinf .= ' group-title="' . htmlspecialchars($categoria, ENT_QUOTES) . '"'
            . ',' . $nomeFinal;

        $out[] = $extinf;
        $out[] = $urls[$i];
    }

    file_put_contents($arquivoFinal, implode("\n", $out) . "\n", LOCK_EX);
}

function normalizar_chave_plataforma($base) {
    $base = strtoupper(trim((string)$base));
    $base = preg_replace('/[^A-Z0-9]+/', '_', $base);
    return trim($base, '_');
}
/* =========================
   ALIASES
========================= */
$ALIASES = [
    "BLOBO" => "GLOBO",
    "TV_GLOBO" => "GLOBO",
    "GLOBOTV" => "GLOBO",

    "SPORT" => "SPORTTV",
    "SPOR" => "SPORTTV",
    "SPOR_TV" => "SPORTTV",

    "ADULTO" => "ADULTO_TV",
    "MAIS_18" => "ADULTO_TV",
    "18" => "ADULTO_TV",

    "PRIME" => "AMAZON",
    "AMAZONPRIME" => "AMAZON",
];

/* =========================
   PLATAFORMAS (inclui Globoplay/Netflix/Amazon filmes)
========================= */
$PLATAFORMAS = [
    "GLOBO" => [
        "nome" => "GLOBO canal",
        "categoria" => cat_icon("CANAL") . "  ▶️ GLOBO",
        "logo" => "https://static.wikia.nocookie.net/logopedia/images/3/35/TVGlobo2025.png/revision/latest?cb=20250403003551"
    ],
    "SBT" => [
        "nome" => "SBT canal",
        "categoria" => cat_icon("CANAL") . "  ▶️ SBT",
        "logo" => "https://static.wikia.nocookie.net/logos/images/8/81/SBT_Logo_2004.png/revision/latest?cb=20230302235717&path-prefix=pt-br"
    ],
    "RECORD" => [
        "nome" => "RECORD canal",
        "categoria" => cat_icon("CANAL") . "  ▶️ RECORD",
        "logo" => "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQS5xJCGPcVjOJkz7HDIFbC_tUNy0h9TQ8z4Q&s"
    ],
    "BAND" => [
        "nome" => "BAND canal",
        "categoria" => cat_icon("CANAL") . "  ▶️ BAND",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/9/91/Band_logo_2021.svg/512px-Band_logo_2021.svg.png"
    ],

    /* ✅ SPORT / SPORTTV */
    "SPORTTV" => [
        "nome" => "SPORT canal",
        "categoria" => cat_icon("CANAIS") . "  ⚽ SPORT",
        "logo" => "https://marcasmais.com.br/wp-content/uploads/2023/08/Sportv-Logo.jpg"
    ],

    /* ✅ SÉRIES PREMIUM */
    "SERIES_PREMIUM" => [
        "nome" => "SÉRIES PREMIUM",
        "categoria" => cat_icon("SERIES") . "  🍿 SÉRIES",
        "logo" => "https://marcasmais.com.br/wp-content/uploads/2023/08/Sportv-Logo.jpg"
    ],

    /* ✅ ANIME / DESENHOS */
    "ANIME" => [
        "nome" => "ANIME / DESENHOS",
        "categoria" => cat_icon("CANAIS") . "  🐉 ANIME",
        "logo" => "https://images.seeklogo.com/logo-png/48/1/dragon-ball-goku-logo-png_seeklogo-483554.png"
    ],

    /* ✅ TELECINE */
    "TELECINE" => [
        "nome" => "TELECINE HD-FHD",
        "categoria" => cat_icon("CANAIS") . "  ▶️ TELECINE",
        "logo" => "https://raichu-uploads.s3.amazonaws.com/logo_telecine_bF7TuD.png"
    ],

    /* ✅ GLOBOPLAY */
    "GLOBOPLAY" => [
        "nome" => "GLOBOPLAY",
        "categoria" => cat_icon("TV") . "  📺 GLOBOPLAY",
        "logo" => "https://raichu-uploads.s3.amazonaws.com/logo_globo-com_gQciga.png"
    ],

    /* ✅ SBT SP NOVO (duplicado - usando mesmo ícone) */
    "SBT_SP_01" => [
        "nome" => "SBT SP NOVO",
        "categoria" => cat_icon("CANAIS") . "  📡 SBT SP",
        "logo" => "https://images.seeklogo.com/logo-png/25/2/sbt-logo-png_seeklogo-252496.png"
    ],

    "SBT_SP_02" => [
        "nome" => "SBT SP NOVO",
        "categoria" => cat_icon("CANAIS") . "  📡 SBT SP",
        "logo" => "https://images.seeklogo.com/logo-png/25/2/sbt-logo-png_seeklogo-252496.png"
    ],

    /* ✅ PREMIERE EUA BR */
    "PREMIERE" => [
        "nome" => "PREMIERE EUA BR",
        "categoria" => cat_icon("CANAIS") . "  🏟️ PREMIERE",
        "logo" => "https://s3.glbimg.com/v1/AUTH_f486c675dfaf4c6e96c25f0c21f85eb5/prod/home-share-1b75cdaa.png"
    ],

    /* ✅ BBB 26 VIPER */
    "BBB26_VIPER" => [
        "nome" => "BBB 26 VIPER",
        "categoria" => cat_icon("CANAIS") . "  👁️ BBB 26",
        "logo" => "https://jpimg.com.br/uploads/2026/01/imagem-jvp-2026-01-06t134109.679-750x450.png"
    ],

    /* ✅ AXN */
    "AXN" => [
        "nome" => "AXN",
        "categoria" => cat_icon("CANAIS") . "  🎬 AXN",
        "logo" => "https://cdn.telaviva.com.br/wp-content/uploads/2016/02/Novo-logo-AXN.png"
    ],

    /* ✅ DOCUMENTARIO DISCOVERY */
    "DISCOVERY_DOC" => [
        "nome" => "DOCUMENTARIO DISCOVERY",
        "categoria" => cat_icon("CANAIS") . "  🌍 DOCUMENTÁRIO",
        "logo" => "https://i.pinimg.com/474x/5f/24/02/5f2402df9264e28fc74351acce84d98a.jpg"
    ],

    "HBO" => [
        "nome" => "HBO HD",
        "categoria" => cat_icon("CANAIS") . "  ▶️ HBO",
        "logo" => "https://cdn-icons-png.flaticon.com/512/5968/5968611.png"
    ],
    
    "ADULTO_TV" => [
        "nome" => "ADULTO FUL-HD",
        "categoria" => cat_icon("CANAIS") . "  🔞 ADULTO",
        "logo" => "https://img.freepik.com/vetores-premium/mais-de-18-icones-redondos-proibidos-ilustracao-vetorial-de-dezoito-ou-conteudo-adulto-de-pessoas-mais-velhas_503038-437.jpg"
    ],

    "ADULTO_MOVEO" => [
        "nome" => "ADULTO FUL-HD",
        "categoria" => cat_icon("FILMES") . "  🔞 XXX-RED",
        "logo" => "https://img.freepik.com/vetores-premium/mais-de-18-icones-redondos-proibidos-ilustracao-vetorial-de-dezoito-ou-conteudo-adulto-de-pessoas-mais-velhas_503038-437.jpg"
    ],

    "NETFLIX" => [
        "nome" => "NETFLIX filmes",
        "categoria" => cat_icon("FILMES") . "  ▶️ NETFLIX",
        "logo" => "https://cdn-icons-png.flaticon.com/512/2504/2504929.png"
    ],
    
    "AMAZON" => [
        "nome" => "AMAZON filmes",
        "categoria" => cat_icon("FILMES") . "  ▶️ AMAZON",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/a/a9/Amazon_logo.svg"
    ],

    /* ✅ COMBATE ORIGINAL */
    "COMBATE" => [
        "nome" => "COMBATE canal",
        "categoria" => cat_icon("CANAIS") . "  🥊 COMBATE",
        "logo" => "https://pandorainternet.net/wp-content/uploads/2024/12/Combate.png"
    ],

    /* ✅ GLOBO SP */
    "GLOBO_SP" => [
        "nome" => "GLOBO SP canal",
        "categoria" => cat_icon("CANAIS") . "  ▶️ GLOBO SP",
        "logo" => "https://images.seeklogo.com/logo-png/14/1/tv-globo-logo-png_seeklogo-143446.png"
    ],

    "SERIES" => [
        "nome" => "SERIES",
        "categoria" => cat_icon("SERIES") . "  ▶️ SERIES",
        "logo" => "https://cdn-icons-png.flaticon.com/512/2504/2504929.png"
    ],
    
    "GLOBO_NORDESTE" => [
        "nome" => "GLOBO NORDESTE canal",
        "categoria" => cat_icon("CANAL") . "  ▶️ GLOBO NORDESTE",
        "logo" => "https://static.wikia.nocookie.net/logopedia/images/3/35/TVGlobo2025.png/revision/latest?cb=20250403003551"
    ],

    /* ========================================
       NOVAS CATEGORIAS (CÓPIAS DO COMBATE)
    ======================================== */

    /* ✅ A&E */
    "AE" => [
        "nome" => "A&E canal",
        "categoria" => cat_icon("CANAIS") . "  📺 A&E",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/d/df/A%26E_Network_logo.svg/512px-A%26E_Network_logo.svg.png"
    ],

    /* ✅ AMC */
    "AMC" => [
        "nome" => "AMC canal",
        "categoria" => cat_icon("CANAIS") . "  🎬 AMC",
        "logo" => "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTVrxAPgT69_uu-F6X90VRLZC8tAXQk3kZg5g&s"
    ],

    /* ✅ ANIMAL PLANET */
    "ANIMAL_PLANET" => [
        "nome" => "ANIMAL PLANET canal",
        "categoria" => cat_icon("CANAIS") . "  🐾 ANIMAL PLANET",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/2/20/2018_Animal_Planet_logo.svg/512px-2018_Animal_Planet_logo.svg.png"
    ],

    /* ✅ ARTE */
    "ARTE" => [
        "nome" => "ARTE canal",
        "categoria" => cat_icon("CANAIS") . "  🎨 ARTE",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/6/65/Arte_Logo_2017.svg/512px-Arte_Logo_2017.svg.png"
    ],

    /* ✅ CANAIS FILMES */
    "CANAIS_FILMES" => [
        "nome" => "CANAIS FILMES canal",
        "categoria" => cat_icon("CANAIS") . "  🎥 CANAIS FILMES",
        "logo" => "https://cdn-icons-png.flaticon.com/512/3074/3074767.png"
    ],

    /* ✅ CANAL CURTA */
    "CANAL_CURTA" => [
        "nome" => "CANAL CURTA canal",
        "categoria" => cat_icon("CANAIS") . "  📽️ CANAL CURTA",
        "logo" => "https://upload.wikimedia.org/wikipedia/pt/thumb/5/55/Canal_Curta%21.svg/512px-Canal_Curta%21.svg.png"
    ],

    /* ✅ CANAL GOAT */
    "CANAL_GOAT" => [
        "nome" => "CANAL GOAT canal",
        "categoria" => cat_icon("CANAIS") . "  🐐 CANAL GOAT",
        "logo" => "https://cdn-icons-png.flaticon.com/512/2965/2965358.png"
    ],

    /* ✅ CANAL GOSPEL */
    "CANAL_GOSPEL" => [
        "nome" => "CANAL GOSPEL canal",
        "categoria" => cat_icon("CANAIS") . "  ✝️ CANAL GOSPEL",
        "logo" => "https://cdn-icons-png.flaticon.com/512/3723/3723663.png"
    ],

    /* ✅ CAZE TV */
    "CAZE_TV" => [
        "nome" => "CAZE TV canal",
        "categoria" => cat_icon("CANAIS") . "  📺 CAZE TV",
        "logo" => "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcR5rVZqE_Wq4gZ4rQF3NZ3fH9YwZ4JgZqJP5w&s"
    ],

    /* ✅ CINEBRASILTY */
    "CINEBRASILTY" => [
        "nome" => "CINEBRASILTY canal",
        "categoria" => cat_icon("CANAIS") . "  🎬 CINEBRASILTY",
        "logo" => "https://cdn-icons-png.flaticon.com/512/3237/3237419.png"
    ],

    /* ✅ DESENHOS */
    "DESENHOS" => [
        "nome" => "DESENHOS canal",
        "categoria" => cat_icon("CANAIS") . "  🎨 DESENHOS",
        "logo" => "https://cdn-icons-png.flaticon.com/512/3242/3242257.png"
    ],

    /* ✅ DISCOVER */
    "DISCOVER" => [
        "nome" => "DISCOVER canal",
        "categoria" => cat_icon("CANAIS") . "  🌍 DISCOVER",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/f/f1/2019_Discovery_logo.svg/512px-2019_Discovery_logo.svg.png"
    ],

    /* ✅ DISNEY+ */
    "DISNEY_PLUS" => [
        "nome" => "DISNEY+ canal",
        "categoria" => cat_icon("CANAIS") . "  ✨ DISNEY+",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/3/3e/Disney%2B_logo.svg/512px-Disney%2B_logo.svg.png"
    ],

    /* ✅ DOCUMENTARIOS */
    "DOCUMENTARIOS" => [
        "nome" => "DOCUMENTARIOS canal",
        "categoria" => cat_icon("CANAIS") . "  📚 DOCUMENTÁRIOS",
        "logo" => "https://cdn-icons-png.flaticon.com/512/2490/2490402.png"
    ],

    /* ✅ H&H */
    "HH" => [
        "nome" => "H&H canal",
        "categoria" => cat_icon("CANAIS") . "  🏠 H&H",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d4/Home_%26_Health_logo.svg/512px-Home_%26_Health_logo.svg.png"
    ],

    /* ✅ PARAMOUNT+ */
    "PARAMOUNT_PLUS" => [
        "nome" => "PARAMOUNT+ canal",
        "categoria" => cat_icon("CANAIS") . "  ⭐ PARAMOUNT+",
        "logo" => "https://logodownload.org/wp-content/uploads/2021/03/paramount-plus-logo-0.png"
    ],

    /* ✅ RECOR */
    "RECOR" => [
        "nome" => "RECOR canal",
        "categoria" => cat_icon("CANAIS") . "  📺 RECOR",
        "logo" => "https://i1.r7.com/data/files/2C95/948F/35B7/7306/0135/BC63/3B30/08E3/record_700x525.jpg"
    ],

    /* ✅ SPORT TV */
    "SPORT_TV" => [
        "nome" => "SPORT TV canal",
        "categoria" => cat_icon("CANAIS") . "  ⚽ SPORT TV",
        "logo" => "https://marcasmais.com.br/wp-content/uploads/2023/08/Sportv-Logo.jpg"
    ],

    /* ✅ SPORT TV */
    "RECOR_TV" => [
        "nome" => "RECOR TV HD canal",
        "categoria" => cat_icon("CANAIS") . "  RECOR TV",
        "logo" => "https://upload.wikimedia.org/wikipedia/pt/1/13/Logotipo_da_Rede_Record.png"
    ],
    /* ✅ SPORT TV */
    "BAND_TV" => [
        "nome" => "BAND TV FHD",
        "categoria" => cat_icon("CANAIS") . "  BAND TV",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/2/21/Rede_Bandeirantes_logo_2011.svg"
    ],

    /* ✅ SPORE */
    "SPORE" => [
        "nome" => "SPORT canal",
        "categoria" => cat_icon("CANAIS") . "  ⚽ SPORE",
        "logo" => "https://cdn-icons-png.flaticon.com/512/53/53283.png"
    ],

    /* ✅ SPORTIV */
    "SPORTIV" => [
        "nome" => "SPORTIV canal",
        "categoria" => cat_icon("CANAIS") . "  ⚽ SPORTIV",
        "logo" => "https://cdn-icons-png.flaticon.com/512/924/924514.png"
    ],

    /* ✅ TNT */
    "TNT" => [
        "nome" => "TNT canal",
        "categoria" => cat_icon("CANAIS") . "  💥 TNT",
        "logo" => "https://upload.wikimedia.org/wikipedia/commons/thumb/3/3e/TNT_Logo_2016.svg/512px-TNT_Logo_2016.svg.png"
    ],

    /* ✅ TUR */
    "TUR" => [
        "nome" => "TUR canal",
        "categoria" => cat_icon("CANAIS") . "  📺 TUR",
        "logo" => "https://cdn-icons-png.flaticon.com/512/3178/3178158.png"
    ],
];




/* =========================
   AÇÕES
========================= */
$msg = "";
$totalMerged = file_exists($arquivoMerged) ? count(parse_m3u_urls(file_get_contents($arquivoMerged))) : 0;
$totalFinal  = file_exists($arquivoFinal)  ? count(parse_m3u_urls(file_get_contents($arquivoFinal)))  : 0;

/* Reset */
if (isset($_GET["reset"]) && $_GET["reset"] === "1") {
    @unlink($arquivoMerged);
    @unlink($arquivoFinal);
    log_evento("reset", []);
    header("Location: index.php");
    exit;
}

/* Download (log) */
if (isset($_GET["dl"])) {
    $f = $_GET["dl"] === "merged" ? $arquivoMerged : ($_GET["dl"] === "final" ? $arquivoFinal : "");
    if (!$f || !file_exists($f)) { http_response_code(404); exit("Arquivo não encontrado."); }

    $nome = basename($f);
    log_evento("download", ["arquivo" => $nome, "bytes" => filesize($f)]);

    header("Content-Type: application/octet-stream");
    header('Content-Disposition: attachment; filename="'.$nome.'"');
    header("Content-Length: " . filesize($f));
    readfile($f);
    exit;
}

/* helper backups por usuário */
function backup_user_file($src, $prefix) {
    global $users_bk_dir, $usuario_atual;

    $u = $usuario_atual ?: "user";
    $udir = $users_bk_dir . "/" . preg_replace('/[^a-zA-Z0-9_-]+/', '_', $u);
    if (!is_dir($udir)) @mkdir($udir, 0777, true);

    $dst = $udir . "/" . $prefix . "_" . date("Ymd_His") . ".m3u";
    @copy($src, $dst);
    return $dst;
}

/* 1) UNIR + NOME AUTOMÁTICO POR ARQUIVO */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["merge_com_nome"])) {
    $files = $_FILES["m3us"] ?? null;

    if (!$files) {
        $msg = "❌ Nenhum arquivo enviado.";
    } else {
        $out = ["#EXTM3U"];
        $count = count($files["name"]);
        $totalGeral = 0;

        for ($i = 0; $i < $count; $i++) {
            if (($files["error"][$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) continue;

            $name = $files["name"][$i] ?? "";
            $tmp  = $files["tmp_name"][$i] ?? "";

            if (!preg_match('/\.m3u$/i', $name)) continue;
            if (!file_exists($tmp)) continue;

            $content = file_get_contents($tmp);

            // robusto: lê EXTINF e acha URL
            $entries = parse_m3u_entries($content);

            // se o arquivo tiver só IP:PORT sem EXTINF, ainda assim pega as linhas
            if (count($entries) === 0) {
                $urls_raw = parse_m3u_urls($content);
                $entries = array_map(fn($u) => ["extinf" => "", "url" => $u], $urls_raw);
            }

            if (count($entries) === 0) continue;

            $urls = array_map(fn($e) => $e["url"], $entries);

            $base = normalizar_chave_plataforma(pathinfo($name, PATHINFO_FILENAME));
            if (isset($ALIASES[$base])) $base = $ALIASES[$base];

            if (isset($PLATAFORMAS[$base])) {
                $nomeBase = $PLATAFORMAS[$base]["nome"];
                $logo = $PLATAFORMAS[$base]["logo"];
                $cat  = $PLATAFORMAS[$base]["categoria"];
            } else {
                $nomeBase = ucfirst(strtolower($base));
                $logo = "";
                $cat = "";
            }

            $parte = gerar_m3u_por_nome_base($urls, $nomeBase, $logo, $cat);
            $linhas = preg_split("/\r\n|\n|\r/", trim($parte));

            foreach ($linhas as $ln) {
                if (trim($ln) === "#EXTM3U") continue;
                $out[] = $ln;
            }

            $totalGeral += count($urls);
        }

        if ($totalGeral === 0) {
            $msg = "❌ Nenhuma URL encontrada nos arquivos enviados.";
        } else {
            file_put_contents($arquivoMerged, implode("\n", $out) . "\n", LOCK_EX);
            @unlink($arquivoFinal);

            $bk = backup_user_file($arquivoMerged, "merged");
            log_evento("merge_com_nome", [
                "arquivos_recebidos" => $count,
                "canais_total" => $totalGeral,
                "backup" => basename($bk)
            ]);

            $msg = "✅ Uniu + Nome por arquivo pronto! Total: <b>$totalGeral</b> canais.";
            $totalMerged = $totalGeral;
            $totalFinal = 0;
        }
    }
}

/* 2) SÓ UNIR (mantém EXTINF original) */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["merge_puro"])) {
    $files = $_FILES["m3us"] ?? null;

    if (!$files) {
        $msg = "❌ Nenhum arquivo enviado.";
    } else {
        $out = ["#EXTM3U"];
        $count = count($files["name"]);
        $total = 0;

        for ($i = 0; $i < $count; $i++) {
            if (($files["error"][$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) continue;

            $name = $files["name"][$i] ?? "";
            $tmp  = $files["tmp_name"][$i] ?? "";

            if (!preg_match('/\.m3u$/i', $name)) continue;
            if (!file_exists($tmp)) continue;

            $content = file_get_contents($tmp);
            $entries = parse_m3u_entries($content);

            // se vier só com IP:PORT sem EXTINF, inclui também
            if (count($entries) === 0) {
                $urls_raw = parse_m3u_urls($content);
                foreach ($urls_raw as $u) {
                    $out[] = "#EXTINF:-1,Canal";
                    $out[] = $u;
                    $total++;
                }
                continue;
            }

            foreach ($entries as $e) {
                $out[] = $e["extinf"];
                $out[] = $e["url"];
                $total++;
            }
        }

        if ($total === 0) {
            $msg = "❌ Nenhum canal encontrado (EXTINF + URL ou IP:PORT).";
        } else {
            file_put_contents($arquivoMerged, implode("\n", $out) . "\n", LOCK_EX);
            @unlink($arquivoFinal);

            $bk = backup_user_file($arquivoMerged, "merged");
            log_evento("merge_puro", [
                "arquivos_recebidos" => $count,
                "canais_total" => $total,
                "backup" => basename($bk)
            ]);

            $msg = "✅ Uniu puro com sucesso! Total: <b>$total</b> canais.";
            $totalMerged = $total;
            $totalFinal = 0;
        }
    }
}

/* 3) RENOMEAR merged.m3u */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["renomear_plataforma"])) {
    if (!file_exists($arquivoMerged)) {
        $msg = "❌ Primeiro você precisa unir (gerar merged.m3u).";
    } else {
        $key = normalizar_chave_plataforma($_POST["plataforma"] ?? "");
        if (isset($ALIASES[$key])) $key = $ALIASES[$key];

        if (!isset($PLATAFORMAS[$key])) {
            $msg = "❌ Plataforma inválida.";
        } else {
            $content = file_get_contents($arquivoMerged);
            $urls = parse_m3u_urls($content);

            if (count($urls) === 0) {
                $msg = "❌ merged.m3u não tem URLs.";
            } else {
                $nomeBase = $PLATAFORMAS[$key]["nome"];
                $cat      = $PLATAFORMAS[$key]["categoria"];
                $logo     = $PLATAFORMAS[$key]["logo"];

                gerar_final_padronizado($urls, $nomeBase, $cat, $logo, $arquivoFinal);

                $bk = backup_user_file($arquivoFinal, "final");
                log_evento("renomear", [
                    "plataforma" => $key,
                    "canais_total" => count($urls),
                    "backup" => basename($bk)
                ]);

                $msg = "✅ Renomeado tudo! Total: <b>" . count($urls) . "</b> canais (final.m3u pronto).";
                $totalFinal = count($urls);
            }
        }
    }
}

/* Reconta totals */
if (file_exists($arquivoMerged)) $totalMerged = count(parse_m3u_urls(file_get_contents($arquivoMerged)));
if (file_exists($arquivoFinal))  $totalFinal  = count(parse_m3u_urls(file_get_contents($arquivoFinal)));

/* Limites atuais do PHP (diagnóstico) */
$max_file_uploads = ini_get("max_file_uploads");
$post_max_size    = ini_get("post_max_size");
$upload_max_filesize = ini_get("upload_max_filesize");
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NOMBRE</title>
<link rel="stylesheet" href="index.css">
</head>
<body>

<div class="wrap">
    <div class="top">
        <div class="brand">
            <div class="dot"></div>
            <div>
                <div class="title">Torino</div>
                <div class="sub">
                    Logado como: <b><?= h($usuario_atual) ?></b>
                    <?php if ($tempo_restante > 0): ?>
                        <span class="muted">• expira em <?= (int)ceil($tempo_restante/3600) ?>h</span>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="right">
            <?php if ($usuario_atual === "admin"): ?>
                <a class="btn ghost" href="admin.php">🧩 Admin</a>
            <?php endif; ?>
            <a class="btn ghost" href="?reset=1" onclick="return confirm('Resetar tudo?')">♻️ Resetar</a>
            <a class="btn ghost" href="?logout=1">🚪 Sair</a>
        </div>
    </div>

    <?php if ($msg): ?>
        <div class="msg ok"><?= $msg ?></div>
    <?php endif; ?>

    <div class="grid">

        <div class="card">
            <h3>📂 Carregar arquivos M3U</h3>

            <form method="POST" enctype="multipart/form-data" class="form">
                <label>Selecione vários arquivos .m3u</label>
                <input type="file" name="m3us[]" accept=".m3u" multiple required>

                <button class="btn primary" type="submit" name="merge_com_nome" value="1">
                    ✅ Unir + Nome automático por arquivo
                </button>

                <button class="btn ghost" type="submit" name="merge_puro" value="1">
                    🔥 Só unir (mantém EXTINF original) — sem comer canais
                </button>
            </form>

            <div class="hint">
                ✅ merged.m3u: <b><?= (int)$totalMerged ?></b> streams.
            </div>

            <?php if (file_exists($arquivoMerged)): ?>
                <div class="actions">
                    <a class="btn ghost" href="?dl=merged">⬇️ Baixar merged.m3u</a>
                </div>
            <?php endif; ?>

            <div class="hint warn">
                dev-ops
                <b>dev=<?= h($max_file_uploads) ?></b> •
                <b>pfor<?= h($post_max_size) ?></b> •
                <b>upload_max_filesize=<?= h($upload_max_filesize) ?></b>
            </div>

            <div class="hint">
                ✅ Agora o sistema também aceita listas com linhas <b>IP:PORT</b>ok<b>Ttp</b>.
            </div>
        </div>

        <div class="card">
            <h3>✍️ Renomear merged.m3u (opcional)</h3>

            <form method="POST" class="form">
                <label>Escolha a plataforma para renomear tudo:</label>
                <select name="plataforma" class="select" required>
                    <option value="">Selecione...</option>
                    <?php foreach ($PLATAFORMAS as $k => $v): ?>
                        <option value="<?= h($k) ?>">
                            <?= h($v["nome"]) ?> (<?= h($v["categoria"]) ?>)
                        </option>
                    <?php endforeach; ?>
                </select>

                <button class="btn primary" type="submit" name="renomear_plataforma" value="1">
                    🚀 Renomear tudo e gerar final.m3u (sem limite)
                </button>

                <div class="hint">
                    ✅ final.m3u: <b><?= (int)$totalFinal ?></b> streams.
                </div>

                <?php if (file_exists($arquivoFinal)): ?>
                    <a class="btn ghost" href="?dl=final">⬇️ Baixar final.m3u</a>
                <?php endif; ?>
            </form>

            <div class="hint">
                Use com sabedoria
            </div>
        </div>

</div>

<div class="footer">
    by <b>up</b> e <b>20137</b> •
    pass <b>rot</b> •
    Logs: <b>root</b>
</div>

</div>

