#!/bin/bash
# Static checks of the website in site/ (docs/WEBSITE.md, "Checks"). Run by the CI job "Site", before
# publishing (site.yml here, and the Pages workflow of PassTunnel/passtunnel.github.io on the published
# commit); fine to run locally. Bash and standard tools only, on Linux and macOS:
#
#   scripts/check-site.sh [SITE_DIR]          # SITE_DIR defaults to site/
#
# Fails when an HTML file
#   - has a style attribute, a <style> element, an inline <script> or an on…= event handler
#     (the Content Security Policy blocks them),
#   - lacks the exact Content Security Policy meta tag below,
#   - links to, or loads src/srcset from, a local file that does not exist, or has an in-page #anchor
#     without a matching id,
#   - loads anything from another origin (links to github.com and the site's own address are fine),
#   - has an <img> without alt, width or height.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SITE="$(cd "${1:-$ROOT/site}" && pwd)"

# The policy every page carries. Changing it means changing it here, in every page and in the spec.
CSP="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'"
# The site is served at this address (PassTunnel/passtunnel.github.io deploys it); absolute paths
# below BASE_PATH (with a trailing slash; "/" is the root of the host) map to site/.
SITE_URL="https://passtunnel.github.io/"
BASE_PATH="/"
LINK_HOSTS_RE='^https://(github\.com|passtunnel\.github\.io)(/|$)'

errors=0
error() {
    echo "error: ${1#"$SITE/"}: $2" >&2
    errors=$((errors + 1))
}

# check_local FILE URL: a local path (relative, or absolute below BASE_PATH) must exist.
check_local() {
    local file="$1" url="$2" path target
    path="${url%%#*}"
    path="${path%%\?*}"
    if [[ "$path" == /* ]]; then
        # With BASE_PATH "/" every absolute path qualifies; "/" itself maps to site/index.html below.
        if [[ "$path" != "$BASE_PATH"* && "$path" != "${BASE_PATH%/}" ]]; then
            error "$file" "absolute path outside $BASE_PATH: $url"
            return
        fi
        target="$SITE/${path#"$BASE_PATH"}"
    else
        target="$(dirname "$file")/$path"
    fi
    [[ -z "$path" || "$path" == */ || -d "$target" ]] && target="${target%/}/index.html"
    [[ -f "$target" ]] || error "$file" "missing file: $url"
}

# check_url FILE TAG ATTR URL
check_url() {
    local file="$1" tag="$2" attr="$3" url="$4" ids="$5" rel
    case "$url" in
        "")
            error "$file" "empty $attr in <$tag>" ;;
        "#")
            error "$file" "dead link: href=\"#\"" ;;
        \#*)
            grep -qxF "${url#\#}" <<<"$ids" || error "$file" "no element with id \"${url#\#}\" for $url" ;;
        mailto:*) ;;
        javascript:* | data:* | vbscript:*)
            error "$file" "$attr uses a ${url%%:*}: URL" ;;
        http://* | https://* | //*)
            if [[ "$attr" != href ]]; then
                error "$file" "<$tag> loads from another origin: $url"
            elif [[ "$tag" == link ]]; then
                rel=""
                if [[ "$TAG_TEXT" =~ [[:space:]]rel=\"([^\"]*)\" ]]; then rel="${BASH_REMATCH[1]}"; fi
                if [[ ! "$rel" =~ ^(canonical|alternate)$ || "$url" != "$SITE_URL"* ]]; then
                    error "$file" "<link rel=\"$rel\"> points to another origin: $url"
                fi
            elif [[ ! "$url" =~ $LINK_HOSTS_RE ]]; then
                error "$file" "link to another site (only github.com is allowed): $url"
            fi ;;
        *)
            check_local "$file" "$url" ;;
    esac
}

shopt -s nocasematch
pages=0
while IFS= read -r -d '' file; do
    pages=$((pages + 1))
    # One line per start tag (attributes may span lines in the source).
    tags="$(tr '\n\r\t' '   ' <"$file" | grep -oE '<[A-Za-z][A-Za-z0-9-]*([[:space:]][^>]*)?>' || true)"
    ids="$(grep -oE '[[:space:]]id="[^"]*"' <<<"$tags" | sed -E 's/.*id="([^"]*)"/\1/' || true)"
    csp_count=0

    while IFS= read -r TAG_TEXT; do
        [[ -z "$TAG_TEXT" ]] && continue
        [[ "$TAG_TEXT" =~ ^\<([A-Za-z][A-Za-z0-9-]*) ]] && tag="$(tr '[:upper:]' '[:lower:]' <<<"${BASH_REMATCH[1]}")"

        [[ "$TAG_TEXT" =~ [[:space:]]style[[:space:]]*= ]] && error "$file" "style attribute: $TAG_TEXT"
        [[ "$TAG_TEXT" =~ [[:space:]]on[a-z]+[[:space:]]*= ]] && error "$file" "event handler attribute: $TAG_TEXT"
        [[ "$tag" == style ]] && error "$file" "<style> element (use assets/style.css)"
        if [[ "$tag" == script && ! "$TAG_TEXT" =~ [[:space:]]src= ]]; then
            error "$file" "inline <script> (use a file in assets/)"
        fi
        if [[ "$tag" == meta && "$TAG_TEXT" =~ http-equiv=\"Content-Security-Policy\" ]]; then
            csp_count=$((csp_count + 1))
            [[ "$TAG_TEXT" == *"content=\"$CSP\""* ]] || error "$file" "Content Security Policy changed: $TAG_TEXT"
        fi
        if [[ "$tag" == img ]]; then
            for attr in alt width height; do
                [[ "$TAG_TEXT" =~ [[:space:]]$attr= ]] || error "$file" "<img> without $attr: $TAG_TEXT"
            done
        fi

        rest="$TAG_TEXT"
        while [[ "$rest" =~ [[:space:]](href|src|srcset)=\"([^\"]*)\" ]]; do
            attr="$(tr '[:upper:]' '[:lower:]' <<<"${BASH_REMATCH[1]}")"
            value="${BASH_REMATCH[2]}"
            rest="${rest#*"${BASH_REMATCH[0]}"}"
            if [[ "$attr" == srcset ]]; then
                IFS=',' read -ra candidates <<<"$value"
                for candidate in "${candidates[@]}"; do
                    read -r url _ <<<"$candidate"
                    check_url "$file" "$tag" srcset "$url" "$ids"
                done
            else
                check_url "$file" "$tag" "$attr" "$value" "$ids"
            fi
        done
        # Social preview images and similar: absolute URLs of this site must exist in site/.
        if [[ "$tag" == meta && "$TAG_TEXT" =~ content=\"(${SITE_URL//./\\.}[^\"]*)\" ]]; then
            check_local "$file" "$BASE_PATH${BASH_REMATCH[1]#"$SITE_URL"}"
        fi
    done <<<"$tags"

    [[ "$csp_count" == 1 ]] || error "$file" "expected one Content Security Policy meta tag, found $csp_count"
done < <(find "$SITE" -name '*.html' -print0 | sort -z)
shopt -u nocasematch

[[ "$pages" -gt 0 ]] || { echo "error: no HTML files in $SITE" >&2; exit 1; }
if [[ "$errors" -gt 0 ]]; then
    echo "check-site: $errors problem(s) in $pages page(s)" >&2
    exit 1
fi
echo "check-site: $pages page(s) OK"
