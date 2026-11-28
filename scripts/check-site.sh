#!/bin/bash
# Static checks of the website in site/ (docs/WEBSITE.md, "Checks"). Run by the CI job "Site", before
# publishing (site.yml here, and the Pages workflow of PassTunnel/passtunnel.github.io on the published
# commit); fine to run locally. Bash (3.2 is enough), jq (1.6 or later) and standard tools only, on Linux
# and macOS:
#
#   scripts/check-site.sh [SITE_DIR]          # SITE_DIR defaults to site/
#
# Fails when an HTML file
#   - has a style attribute, a <style> element, an inline <script> or an on…= event handler
#     (the Content Security Policy blocks them); the one inline script allowed is a structured data
#     block written exactly as <script type="application/ld+json">, which browsers never run,
#   - has a structured data block that is not a single JSON object with "@context":
#     "https://schema.org", names a URL of this site that has no file in site/ (or whose #fragment is
#     no id in that file; "@id" values are node names and are not checked), has a dateModified
#     without a matching <time datetime> on the page, or has FAQPage questions and answers that differ
#     from the page's visible FAQ (<details class="faq-item">: the question in <summary><span>, the
#     answer everything after </summary>, compared as plain text, in order),
#   - has a canonical URL (an indexable page) that is not its own address, or has one but no structured
#     data block, or is missing from sitemap.xml,
#   - lacks the exact Content Security Policy meta tag below,
#   - links to, or loads src/srcset from, a local file (or a URL of this site) that does not exist,
#     has an #anchor without a matching id in the page it points to, or links to a page in another
#     language without hreflang set to that page's <html lang>,
#   - has a srcset with a malformed descriptor, with both width (640w) and density (2x) descriptors,
#     or with width descriptors but no sizes,
#   - loads anything from another origin (links to github.com and the site's own address are fine),
#   - has an <img> without alt, width or height,
#   - is one of a set of translations (<link rel="alternate" hreflang>) whose links are not the same on
#     every page of the set (each page listing itself under its own <html lang>, plus x-default), or
#     whose element ids (in order) or number of FAQ items differ from another page of the set; the same
#     alternates must be in sitemap.xml.
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
# The only inline script allowed: a JSON-LD data block (docs/WEBSITE.md, "Structured data").
LD_TAG='<script type="application/ld+json">'
SEP=$'\x1f'

command -v jq >/dev/null || { echo "error: check-site.sh needs jq" >&2; exit 1; }

errors=0
error() {
    echo "error: ${1#"$SITE/"}: $2" >&2
    errors=$((errors + 1))
}

# What the per-page pass learns, for the checks across pages after it (index = page number).
P_FILE=()     # the file
P_LANG=()     # <html lang>
P_CANON=()    # canonical URL
P_ALTS=()     # <link rel="alternate" hreflang> as sorted "hreflang URL" lines
P_IDS=()      # element ids, in page order
P_FAQ=()      # number of visible FAQ items
DEFERRED=""   # links to other pages: FILE, TARGET, FRAGMENT, HREFLANG (or "-" for none), separated by SEP

# resolve_local FILE URL: sets TARGET to the file in site/ that a local URL (relative, or absolute
# below BASE_PATH) names; returns 1 (with an error) for an absolute path outside BASE_PATH.
resolve_local() {
    local file="$1" url="$2" path
    path="${url%%#*}"
    path="${path%%\?*}"
    if [[ "$path" == /* ]]; then
        # With BASE_PATH "/" every absolute path qualifies; "/" itself maps to site/index.html below.
        if [[ "$path" != "$BASE_PATH"* && "$path" != "${BASE_PATH%/}" ]]; then
            error "$file" "absolute path outside $BASE_PATH: $url"
            TARGET=""
            return 1
        fi
        TARGET="$SITE/${path#"$BASE_PATH"}"
    elif [[ -z "$path" ]]; then
        TARGET="$file"
        return 0
    else
        # Relative to the page's folder.
        TARGET="${file%/*}/$path"
    fi
    [[ "$path" == */ || -d "$TARGET" ]] && TARGET="${TARGET%/}/index.html"
    normalise_target
    if [[ "$TARGET" != "$SITE/"* ]]; then
        error "$file" "path outside the site: $url"
        TARGET=""
        return 1
    fi
    return 0
}

# normalise_target: collapses "//", "/./" and "dir/../" in TARGET (an absolute path), so the same file
# always has the same name; in bash, without a subshell per link.
normalise_target() {
    local part n=0 i out=""
    local -a parts stack
    IFS='/' read -ra parts <<<"$TARGET"
    for part in "${parts[@]}"; do
        case "$part" in
            "" | .) ;;
            ..) [[ "$n" -gt 0 ]] && n=$((n - 1)) ;;
            *) stack[n]="$part"; n=$((n + 1)) ;;
        esac
    done
    for ((i = 0; i < n; i++)); do out+="/${stack[i]}"; done
    TARGET="${out:-/}"
}

# check_local FILE URL [HREFLANG]: a local path must exist; a #fragment or a link to another page is
# checked after every page has been read. HREFLANG is the link's hreflang, "-" for none, or "*" for a
# URL that is not a link (structured data, meta tags), whose language is not checked.
check_local() {
    local file="$1" url="$2" hreflang="${3:--}" fragment=""
    resolve_local "$file" "$url" || return 0
    if [[ ! -f "$TARGET" ]]; then
        error "$file" "missing file: $url"
        return 0
    fi
    [[ "$url" == *#* ]] && fragment="${url#*#}"
    if [[ "$TARGET" != "$file" || -n "$fragment" ]] && [[ "$TARGET" == *.html ]]; then
        DEFERRED+="$file$SEP$TARGET$SEP$fragment$SEP$hreflang"$'\n'
    fi
}

# has_line LIST LINE: LIST (newline-separated) contains LINE, in the same letter case (ids, URLs and
# language codes are compared exactly, even while nocasematch is on for tag names).
has_line() {
    local found=1 nocase=0
    shopt -q nocasematch && nocase=1
    shopt -u nocasematch
    [[ $'\n'"$1"$'\n' == *$'\n'"$2"$'\n'* ]] && found=0
    [[ "$nocase" == 1 ]] && shopt -s nocasematch
    return "$found"
}

# check_url FILE TAG ATTR URL IDS
check_url() {
    local file="$1" tag="$2" attr="$3" url="$4" ids="$5" rel hreflang="-"
    if [[ "$tag" =~ ^(a|link)$ && "$TAG_TEXT" =~ [[:space:]]hreflang=\"([^\"]*)\" ]]; then hreflang="${BASH_REMATCH[1]}"; fi
    case "$url" in
        "")
            error "$file" "empty $attr in <$tag>" ;;
        "#")
            error "$file" "dead link: href=\"#\"" ;;
        \#*)
            has_line "$ids" "${url#\#}" || error "$file" "no element with id \"${url#\#}\" for $url" ;;
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
                else
                    check_local "$file" "$BASE_PATH${url#"$SITE_URL"}" "$hreflang"
                fi
            elif [[ ! "$url" =~ $LINK_HOSTS_RE ]]; then
                error "$file" "link to another site (only github.com is allowed): $url"
            elif [[ "$url" == "$SITE_URL"* ]]; then
                check_local "$file" "$BASE_PATH${url#"$SITE_URL"}" "$hreflang"
            fi ;;
        *)
            check_local "$file" "$url" "$hreflang" ;;
    esac
}

# The structured data and the visible FAQ of one page, in one jq run (the page on one line as $page,
# LD_TAG as $ld). The page goes in with --rawfile, not -R: jq 1.7.1 breaks a multibyte character that
# straddles its 16 KB raw-input buffer, which made Turkish text differ at random. Prints lines "KIND<TAB>TEXT": blocks (the number of JSON-LD blocks), faq (the
# number of visible FAQ items), url (a URL of this site outside "@id"), error (a problem to report).
# Plain text: tags removed, the common entities decoded, whitespace collapsed, as a reader (and a
# search engine) sees it; JSON strings get the same whitespace rule.
# shellcheck disable=SC2016 # $names below are jq variables.
JQ_PAGE='
def norm: gsub("\\s+"; " ") | sub("^ "; "") | sub(" $"; "");
def plain: gsub("<[^>]*>"; "") | gsub("&nbsp;"; " ") | gsub("&lt;"; "<") | gsub("&gt;"; ">")
    | gsub("&quot;"; "\"") | gsub("&#39;"; "'"'"'") | gsub("&amp;"; "&") | norm;
($page | split($ld) | .[1:]) as $parts
| [ $parts | to_entries[] | .key as $i | .value
    | if (split("</script>") | length) < 2 then {i: $i, error: "has no </script>"}
      else (split("</script>")[0] | try fromjson catch null) as $json
      | if ($json | type) == "object" and $json["@context"] == "https://schema.org" then {i: $i, json: $json}
        else {i: $i, error: "is not one JSON object with \"@context\": \"https://schema.org\""} end
      end ] as $blocks
| [ $blocks[] | .json // empty ] as $docs
| [ $page | split("<details class=\"faq-item\"") | .[1:][]
    | if (split("</details>") | length) < 2 then {error: "has no </details>"}
      else split("</details>")[0]
      | if (split("<summary><span>") | length) < 2 or (split("</summary>") | length) < 2
        then {error: "has no <summary><span>…</summary>"}
        else {q: (split("<summary><span>")[1] | split("</span>")[0] | plain),
              a: (split("</summary>")[1:] | join("</summary>") | plain)} end
      end ] as $visible
| [ $docs[] | .. | objects | select(.["@type"] == "Question")
    | {q: (.name // "" | tostring | norm), a: (.acceptedAnswer.text // "" | tostring | norm)} ] as $structured
| "blocks\t\($parts | length)",
  "faq\t\($visible | length)",
  ($blocks[] | select(.error) | "error\tJSON-LD block \(.i + 1) \(.error)"),
  ($visible | to_entries[] | select(.value.error) | "error\tFAQ item \(.key + 1) \(.value.error)"),
  ([ $docs[] | paths(type == "string") as $p | select($p[-1] != "@id") | getpath($p)
     | select(startswith($site)) ] | unique[] | "url\t\(.)"),
  ($docs[] | .. | objects | .dateModified? // empty | tostring | . as $date
     | select($page | contains("<time datetime=\"" + $date + "\"") | not)
     | "error\tJSON-LD dateModified \($date) has no matching <time datetime=\"\($date)\"> on the page"),
  (if ($visible | length) != ($structured | length) then
     "error\tthe visible FAQ has \($visible | length) question(s), the JSON-LD FAQPage \($structured | length)"
   else
     range(0; $visible | length) as $n | $visible[$n] as $v | $structured[$n] as $s
     | (if $v.q != $s.q then "error\tthe question of FAQ \($n + 1) differs from the JSON-LD FAQPage:\\n  page:    \($v.q)\\n  JSON-LD: \($s.q)" else empty end),
       (if $v.a != $s.a then "error\tthe answer of FAQ \($n + 1) differs from the JSON-LD FAQPage:\\n  page:    \($v.a)\\n  JSON-LD: \($s.a)" else empty end)
   end)
'

# check_page_data FILE FLAT TAG_COUNT: the structured data and FAQ of one page (FLAT is the page on
# one line, TAG_COUNT the number of JSON-LD script tags the tag scan saw, in any letter case).
check_page_data() {
    local file="$1" flat="$2" tag_count="$3" kind text count=0 faq=0 out
    if ! out="$(jq -n -r --rawfile page /dev/stdin --arg ld "$LD_TAG" --arg site "$SITE_URL" "$JQ_PAGE" <<<"$flat")"; then
        error "$file" "jq could not read the page"
        return 0
    fi
    while IFS=$'\t' read -r kind text; do
        case "$kind" in
            blocks) count="$text" ;;
            faq) faq="$text" ;;
            url) check_local "$file" "$BASE_PATH${text#"$SITE_URL"}" "*" ;;
            error) error "$file" "${text//\\n/$'\n'}" ;;
        esac
    done <<<"$out"
    if [[ "$count" != "$tag_count" ]]; then
        error "$file" "write each JSON-LD script tag exactly as $LD_TAG"
    fi
    if [[ "$count" == 0 && -n "$canon" ]]; then
        error "$file" "page with a canonical URL has no JSON-LD block"
    fi
    FAQ_COUNT="$faq"
}

# page_index FILE: sets IDX to the page number of FILE, or -1.
page_index() {
    local i
    IDX=-1
    for ((i = 0; i < ${#P_FILE[@]}; i++)); do
        [[ "${P_FILE[i]}" == "$1" ]] && { IDX=$i; return 0; }
    done
    return 0
}

shopt -s nocasematch
pages=0
while IFS= read -r -d '' file; do
    flat="$(tr '\n\r\t' '   ' <"$file")"
    # One line per start tag (attributes may span lines in the source).
    tags="$(grep -oE '<[A-Za-z][A-Za-z0-9-]*([[:space:]][^>]*)?>' <<<"$flat" || true)"
    ids="$(grep -oE '[[:space:]]id="[^"]*"' <<<"$tags" | sed -E 's/.*id="([^"]*)"/\1/' || true)"
    csp_count=0
    ld_count=0
    lang=""
    canon=""
    alts=""

    while IFS= read -r TAG_TEXT; do
        [[ -z "$TAG_TEXT" ]] && continue
        # Tag and attribute names are compared with nocasematch on, so they need no lowercasing.
        [[ "$TAG_TEXT" =~ ^\<([A-Za-z][A-Za-z0-9-]*) ]] && tag="${BASH_REMATCH[1]}"

        [[ "$TAG_TEXT" =~ [[:space:]]style[[:space:]]*= ]] && error "$file" "style attribute: $TAG_TEXT"
        [[ "$TAG_TEXT" =~ [[:space:]]on[a-z]+[[:space:]]*= ]] && error "$file" "event handler attribute: $TAG_TEXT"
        [[ "$tag" == style ]] && error "$file" "<style> element (use assets/style.css)"
        if [[ "$tag" == script && "$TAG_TEXT" == "$LD_TAG" ]]; then
            ld_count=$((ld_count + 1))
        elif [[ "$tag" == script && ! "$TAG_TEXT" =~ [[:space:]]src= ]]; then
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
        if [[ "$tag" == html && "$TAG_TEXT" =~ [[:space:]]lang=\"([^\"]*)\" ]]; then
            lang="${BASH_REMATCH[1]}"
        fi
        if [[ "$tag" == link && "$TAG_TEXT" =~ [[:space:]]rel=\"canonical\" ]]; then
            [[ -z "$canon" ]] || error "$file" "more than one canonical link"
            if [[ "$TAG_TEXT" =~ [[:space:]]href=\"([^\"]*)\" ]]; then canon="${BASH_REMATCH[1]}"; else canon="-"; fi
        fi
        if [[ "$tag" == link && "$TAG_TEXT" =~ [[:space:]]hreflang=\"([^\"]*)\" ]]; then
            hreflang="${BASH_REMATCH[1]}"
            if [[ "$TAG_TEXT" =~ [[:space:]]href=\"([^\"]*)\" ]]; then
                alts+="$hreflang ${BASH_REMATCH[1]}"$'\n'
            fi
        fi

        rest="$TAG_TEXT"
        while [[ "$rest" =~ [[:space:]](href|src|srcset)=\"([^\"]*)\" ]]; do
            attr="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            rest="${rest#*"${BASH_REMATCH[0]}"}"
            if [[ "$attr" == srcset ]]; then
                # Candidates are "URL", "URL 2x" (density) or "URL 640w" (width, which needs sizes);
                # one srcset uses one kind.
                IFS=',' read -ra candidates <<<"$value"
                kinds=""
                for candidate in "${candidates[@]}"; do
                    descriptor=""
                    read -r url descriptor <<<"$candidate"
                    check_url "$file" "$tag" srcset "$url" "$ids"
                    if [[ "$descriptor" =~ ^[0-9]+w$ ]]; then
                        kinds="${kinds/w/}w"
                    elif [[ -z "$descriptor" || "$descriptor" =~ ^[0-9]+(\.[0-9]+)?x$ ]]; then
                        kinds="${kinds/x/}x"
                    else
                        error "$file" "bad srcset descriptor \"$descriptor\" for $url"
                    fi
                done
                [[ ${#kinds} -le 1 ]] || error "$file" "srcset mixes width and density descriptors: $value"
                if [[ "$kinds" == *w* && ! "$TAG_TEXT" =~ [[:space:]]sizes=\"[^\"]+\" ]]; then
                    error "$file" "srcset with width descriptors but no sizes: $TAG_TEXT"
                fi
            else
                check_url "$file" "$tag" "$attr" "$value" "$ids"
            fi
        done
        # Social preview images and similar: absolute URLs of this site must exist in site/.
        if [[ "$tag" == meta && "$TAG_TEXT" =~ content=\"(${SITE_URL//./\\.}[^\"]*)\" ]]; then
            check_local "$file" "$BASE_PATH${BASH_REMATCH[1]#"$SITE_URL"}" "*"
        fi
    done <<<"$tags"

    # The canonical URL is this page's own address on the site.
    if [[ -n "$canon" ]]; then
        if [[ "$canon" != "$SITE_URL"* ]]; then
            error "$file" "canonical URL is not on $SITE_URL: $canon"
        elif resolve_local "$file" "$BASE_PATH${canon#"$SITE_URL"}" && [[ "$TARGET" != "$file" ]]; then
            error "$file" "canonical URL $canon is the address of ${TARGET#"$SITE/"}, not of this page"
        fi
    fi
    check_page_data "$file" "$flat" "$ld_count"
    [[ "$csp_count" == 1 ]] || error "$file" "expected one Content Security Policy meta tag, found $csp_count"

    P_FILE[pages]="$file"
    P_LANG[pages]="$lang"
    P_CANON[pages]="$canon"
    P_ALTS[pages]="$([[ -z "$alts" ]] || LC_ALL=C sort -u <<<"${alts%$'\n'}")"
    P_IDS[pages]="$ids"
    P_FAQ[pages]="$FAQ_COUNT"
    pages=$((pages + 1))
done < <(find "$SITE" -name '*.html' -print0 | sort -z)
# From here on every comparison is exact.
shopt -u nocasematch

[[ "$pages" -gt 0 ]] || { echo "error: no HTML files in $SITE" >&2; exit 1; }

# Links to other pages: the #fragment must be an id there, and a page in another language needs
# hreflang with that language.
while IFS="$SEP" read -r file target fragment hreflang; do
    [[ -z "$file" ]] && continue
    page_index "$file"
    [[ "$IDX" -ge 0 ]] || continue
    from_lang="${P_LANG[IDX]}"
    page_index "$target"
    if [[ "$IDX" -lt 0 ]]; then
        error "$file" "link to ${target#"$SITE/"}, which is not a page of the site"
        continue
    fi
    to_lang="${P_LANG[IDX]}"
    if [[ -n "$fragment" ]] && ! has_line "${P_IDS[IDX]}" "$fragment"; then
        error "$file" "no element with id \"$fragment\" in ${target#"$SITE/"}"
    fi
    # x-default names the page for every other language, whatever its own; "*" is not a link.
    [[ "$hreflang" == x-default || "$hreflang" == "*" ]] && continue
    if [[ "$hreflang" != - && "$hreflang" != "$to_lang" ]]; then
        error "$file" "hreflang=\"$hreflang\" on a link to ${target#"$SITE/"}, whose language is \"$to_lang\""
    elif [[ "$hreflang" == - && -n "$to_lang" && "$to_lang" != "$from_lang" ]]; then
        error "$file" "link to ${target#"$SITE/"} ($to_lang) without hreflang=\"$to_lang\""
    fi
done < <(sort -u <<<"$DEFERRED")

# Translations: every page of a set lists the same alternates, itself among them, and they match.
for ((i = 0; i < pages; i++)); do
    alts="${P_ALTS[i]}"
    [[ -z "$alts" ]] && continue
    file="${P_FILE[i]}"
    has_line "$alts" "${P_LANG[i]} ${P_CANON[i]}" ||
        error "$file" "the hreflang links do not list this page (${P_CANON[i]}) as \"${P_LANG[i]}\""
    [[ "$alts" == *"x-default "* ]] || error "$file" "the hreflang links have no x-default"
    while read -r hreflang url; do
        [[ "$hreflang" == x-default || "$url" != "$SITE_URL"* ]] && continue
        resolve_local "$file" "$BASE_PATH${url#"$SITE_URL"}" || continue
        page_index "$TARGET"
        j="$IDX"
        [[ "$j" -ge 0 ]] || continue    # reported as a missing file
        [[ "${P_LANG[j]}" == "$hreflang" ]] ||
            error "$file" "hreflang=\"$hreflang\" for $url, whose <html lang> is \"${P_LANG[j]}\""
        [[ "$j" == "$i" ]] && continue
        if [[ "${P_ALTS[j]}" != "$alts" ]]; then
            error "${P_FILE[j]}" "its hreflang links differ from those of ${file#"$SITE/"}"
        elif [[ "$j" -lt "$i" ]]; then
            continue    # the same pair, compared from page j already
        fi
        if [[ "${P_IDS[j]}" != "${P_IDS[i]}" ]]; then
            error "${P_FILE[j]}" "its element ids differ from those of ${file#"$SITE/"} (a translation keeps the same sections and ids):"$'\n'"$(diff <(echo "${P_IDS[i]}") <(echo "${P_IDS[j]}") | grep '^[<>]' | head -n 6 || true)"
        fi
        if [[ "${P_FAQ[j]}" != "${P_FAQ[i]}" ]]; then
            error "${P_FILE[j]}" "${P_FAQ[j]} FAQ item(s), ${file#"$SITE/"} has ${P_FAQ[i]}"
        fi
    done <<<"$alts"
done

# sitemap.xml lists every page with a canonical URL, every URL it lists exists, and its xhtml:link
# alternates are the page's.
sitemap="$SITE/sitemap.xml"
if [[ -f "$sitemap" ]]; then
    # One line per <url>: the loc, a tab, then its alternates as "hreflang URL" separated by SEP.
    # shellcheck disable=SC2016 # $sep is a jq variable.
    entries="$(tr '\n\r\t' '   ' <"$sitemap" | jq -n -r --rawfile xml /dev/stdin --arg sep "$SEP" '
        $xml | split("<url>")[1:][] | split("</url>")[0]
        | (capture("<loc>\\s*(?<loc>[^<]*?)\\s*</loc>").loc // "") as $loc
        | [ scan("<xhtml:link\\s+rel=\"alternate\"\\s+hreflang=\"([^\"]*)\"\\s+href=\"([^\"]*)\"") | join(" ") ]
        | sort | unique | "\($loc)\t\(join($sep))"')"
    while IFS=$'\t' read -r loc sm_alts; do
        [[ -z "$loc" ]] && continue
        if [[ "$loc" != "$SITE_URL"* ]]; then
            error "$sitemap" "URL of another site: $loc"
            continue
        fi
        check_local "$sitemap" "$BASE_PATH${loc#"$SITE_URL"}"
    done <<<"$entries"
    for ((i = 0; i < pages; i++)); do
        canon="${P_CANON[i]}"
        [[ -z "$canon" ]] && continue
        line=""
        while IFS= read -r entry; do
            [[ "${entry%%$'\t'*}" == "$canon" ]] && { line="$entry"; break; }
        done <<<"$entries"
        if [[ -z "$line" ]]; then
            error "$sitemap" "no <url> for ${P_FILE[i]#"$SITE/"} ($canon)"
            continue
        fi
        sm_alts="${line#*$'\t'}"
        if [[ "${sm_alts//$SEP/$'\n'}" != "${P_ALTS[i]}" ]]; then
            error "$sitemap" "the xhtml:link alternates of $canon differ from the hreflang links of ${P_FILE[i]#"$SITE/"}"
        fi
    done
else
    error "$sitemap" "missing"
fi

if [[ "$errors" -gt 0 ]]; then
    echo "check-site: $errors problem(s) in $pages page(s)" >&2
    exit 1
fi
echo "check-site: $pages page(s) OK"
