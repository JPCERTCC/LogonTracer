#!/bin/sh
# Download the browser JS/CSS that the templates reference with
#   vendor_asset('/static/vendor/<path>', '<cdn url>')
# into static/vendor, so the image serves them locally (LOGONTRACER_OFFLINE=1,
# no CDN requests from the analyst's browser). The list is read from the
# templates themselves: a new asset in a template is fetched without editing
# this file. Fails the build on any download error.
#
# Usage: fetch_vendor_assets.sh <static/vendor dir> [templates dir]
set -eu

DEST="${1:?usage: $0 <static/vendor dir> [templates dir]}"
TEMPLATES="${2:-$(dirname "$DEST")/../templates}"
[ -d "$TEMPLATES" ] || { echo "templates not found: $TEMPLATES" >&2; exit 1; }
VENDOR_ROOT="$(dirname "$(dirname "$DEST")")"   # LogonTracer root (parent of static/)

fetch() {  # fetch <https url> <absolute destination file>
    case "$1" in https://*) ;; *) echo "refusing non-https url: $1" >&2; exit 1 ;; esac
    mkdir -p "$(dirname "$2")"
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 -o "$2.tmp" "$1"
    mv "$2.tmp" "$2"
    echo "  $1"
}

pairs=$(grep -rhoE "vendor_asset\('/static/vendor/[^']+', *'https://[^']+'\)" "$TEMPLATES" \
        | sed -E "s#vendor_asset\('(/static/vendor/[^']+)', *'(https://[^']+)'\)#\1 \2#" | sort -u)
[ -n "$pairs" ] || { echo "no vendor_asset() references found in $TEMPLATES" >&2; exit 1; }

echo "[+] vendor assets -> $DEST"
echo "$pairs" | while read -r local url; do
    case "$local" in */../*|*/..) echo "refusing path: $local" >&2; exit 1 ;; esac
    fetch "$url" "$VENDOR_ROOT$local"
done

# Font files referenced relatively from the icon CSS (../fonts, ../webfonts).
FA4="$DEST/font-awesome/4.2.0"
if [ -f "$FA4/css/font-awesome.min.css" ]; then
    for f in fontawesome-webfont.eot fontawesome-webfont.svg fontawesome-webfont.ttf \
             fontawesome-webfont.woff FontAwesome.otf; do
        fetch "https://maxcdn.bootstrapcdn.com/font-awesome/4.2.0/fonts/$f" "$FA4/fonts/$f"
    done
fi
FA5="$DEST/fontawesome-free/5.11.2"
if [ -f "$FA5/css/all.css" ]; then
    for w in fa-brands-400 fa-regular-400 fa-solid-900; do
        for ext in eot svg ttf woff woff2; do
            fetch "https://use.fontawesome.com/releases/v5.11.2/webfonts/$w.$ext" "$FA5/webfonts/$w.$ext"
        done
    done
fi
echo "[+] vendor assets done"
