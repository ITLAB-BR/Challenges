<?php
/**
* MU-plugin: CSP Nonce Injector for WordPress
*
* Objetivo: gerar um nonce por requisição, inserir o atributo nonce em scripts/styles
* <?php
<?php
/**
* MU-plugin: CSP Nonce Injector for WordPress
*
* Objetivo: gerar um nonce por requisição, inserir o atributo nonce em scripts/styles
* enfileirados pelo WordPress e enviar o header Content-Security-Policy que inclui
* o nonce. Tem também um fallback (opcional) que injeta nonce em tags <script>
* impressas diretamente no HTML quando necessário.
*
* Instruções de instalação:
*/

if (!defined('ABSPATH')) {
    exit;
}

// ---------- Configurações (ajuste conforme necessário) ----------
if (!defined('CSP_NONCE_CUSTOM_DIRECTIVES')) {
    define('CSP_NONCE_CUSTOM_DIRECTIVES', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://app.privally.global; ");
}

if (!defined('CSP_NONCE_ENABLE_OUTPUT_BUFFER_FALLBACK')) {
    define('CSP_NONCE_ENABLE_OUTPUT_BUFFER_FALLBACK', true);
}

// Se true, adiciona nonce também em tags <link rel="stylesheet"> (útil se usar style-src 'nonce-...').
if (!defined('CSP_NONCE_ADD_NONCE_TO_LINKS')) {
    define('CSP_NONCE_ADD_NONCE_TO_LINKS', false);
}

function csp_nonce_get() {
    if (!empty($GLOBALS['csp_nonce'])) {
        return $GLOBALS['csp_nonce'];
    }

    try {
        $bytes = random_bytes(18);
        $nonce = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    } catch (Exception $e) {
        $nonce = substr(bin2hex(openssl_random_pseudo_bytes(12)), 0, 24);
    }

    $GLOBALS['csp_nonce'] = $nonce;
    return $nonce;
}

// ----------------------------------------------------------------------------------
// Envia o header CSP com o nonce (executa cedo, mas após geração do nonce)
// Usamos send_headers hook para garantir que headers ainda podem ser enviados.
// ----------------------------------------------------------------------------------
add_action('send_headers', function() {
    $nonce = csp_nonce_get();

    // Observação: 'strict-dynamic' só tem efeito quando usado com nonce or hashes e 'unsafe-inline' não deve ser usado.
    $script_directive = "script-src 'self' 'nonce-{$nonce}' 'strict-dynamic' https:;";

    $directives = trim($script_directive . ' ' . CSP_NONCE_CUSTOM_DIRECTIVES);

    header("Content-Security-Policy: {$directives}");
});

// ----------------------------------------------------------------------------------
// Adiciona nonce aos scripts enfileirados pelo WP (wp_enqueue_script)
// - Hook: script_loader_tag
// ----------------------------------------------------------------------------------
add_filter('script_loader_tag', function($tag, $handle, $src) {
    $nonce = csp_nonce_get();
    if (empty($nonce)) return $tag;

    if (stripos($tag, ' nonce=') !== false) {
        return $tag;
    }

    $tag = preg_replace('/<script(\s+)/i', "<script nonce=\"{$nonce}\" ", $tag, 1);
    return $tag;
}, 10, 3);

// ----------------------------------------------------------------------------------
// Adiciona nonce aos styles enfileirados (opcional) - <link rel="stylesheet" ...>
// Útil se você optar por usar style-src 'nonce-...'
// ----------------------------------------------------------------------------------
if (CSP_NONCE_ADD_NONCE_TO_LINKS) {
    add_filter('style_loader_tag', function($tag, $handle, $href, $media) {
        $nonce = csp_nonce_get();
        if (empty($nonce)) return $tag;
        if (stripos($tag, ' nonce=') !== false) return $tag;
        $tag = preg_replace('/<link(\s+)/i', "<link nonce=\"{$nonce}\" ", $tag, 1);
        return $tag;
    }, 10, 4);
}

// ----------------------------------------------------------------------------------
// WP >= 5.7: filtro para scripts inline gerados por wp_add_inline_script
// Nome do filtro: print_inline_script_tag
// ----------------------------------------------------------------------------------
if (has_filter('print_inline_script_tag')) {
    add_filter('print_inline_script_tag', function($tag) {
        $nonce = csp_nonce_get();
        if (empty($nonce)) return $tag;
        if (stripos($tag, ' nonce=') !== false) return $tag;
        $tag = preg_replace('/<script(\s*)/i', "<script nonce=\"{$nonce}\" ", $tag, 1);
        return $tag;
    });
}

// ----------------------------------------------------------------------------------
// Fallback: bufferiza a saída HTML e injeta nonce em <script> tags que não receberam um
// Esse fallback é opcional e ativado pela constante CSP_NONCE_ENABLE_OUTPUT_BUFFER_FALLBACK
// ----------------------------------------------------------------------------------
if (CSP_NONCE_ENABLE_OUTPUT_BUFFER_FALLBACK) {
    add_action('template_redirect', function() {
        if (!is_admin() && !did_action('rest_api_init')) {
            ob_start('csp_nonce_output_buffer_callback');
        }
    });

    function csp_nonce_output_buffer_callback($html) {
        $nonce = csp_nonce_get();
        if (empty($nonce) || empty($html)) return $html;

        $html = preg_replace_callback(
            '#<script\b([^>]*)>#i',
            function($m) use ($nonce) {
                $attrs = $m[1];
                if (stripos($attrs, ' nonce=') !== false) return "<script{$attrs}>";
                return "<script nonce=\"{$nonce}\"{$attrs}>";
            },
            $html
        );

        if (CSP_NONCE_ADD_NONCE_TO_LINKS) {
            $html = preg_replace_callback(
                '#<link\b([^>]*)>#i',
                function($m) use ($nonce) {
                    $attrs = $m[1];
                    if (stripos($attrs, 'rel=') !== false && stripos($attrs, 'stylesheet') !== false) {
                        if (stripos($attrs, ' nonce=') !== false) return "<link{$attrs}>";
                        return "<link nonce=\"{$nonce}\"{$attrs}>";
                    }
                    return "<link{$attrs}>";
                },
                $html
            );
        }

        return $html;
    }
}

if (!defined('CSP_NONCE_DEBUG_HTML_COMMENT')) {
    define('CSP_NONCE_DEBUG_HTML_COMMENT', false);
}
if (CSP_NONCE_DEBUG_HTML_COMMENT) {
    add_action('wp_footer', function() {
        $nonce = csp_nonce_get();
        echo "<!-- CSP nonce: {$nonce} -->\n";
    }, 9999);
}

// ----------------------------------------------------------------------------------
// Filtros adicionais: permita que outros plugins/leitores obtenham o nonce via função/pseudo-filter
// ----------------------------------------------------------------------------------
function csp_nonce_get_for_plugins() {
    return csp_nonce_get();
}
add_filter('csp_nonce_value', 'csp_nonce_get_for_plugins');
