#!/usr/bin/env bash
#
# Builds the Qartvelo Guard release.
#
#   scripts/build.sh               upload-ready zip in dist/ (Plugins > Add New > Upload)
#   scripts/build.sh --wporg       same, plus the WordPress.org submission checks
#   scripts/build.sh --svn PATH    also syncs the build into a WordPress.org SVN
#                                  checkout (trunk/, tags/<version>/, assets/) and
#                                  prints the svn commands to review and commit
#
# Output: dist/qartvelo-guard-<version>.zip and a .sha256 file next to it.
# The zip holds one top folder, qartvelo-guard/, as WordPress expects.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SLUG="qartvelo-guard"
SRC="$ROOT/$SLUG"
DIST="$ROOT/dist"
STAGE="$DIST/build/$SLUG"
ASSETS="$ROOT/wporg-assets"

WPORG=0
SVN_DIR=""
while [ $# -gt 0 ]; do
	case "$1" in
		--wporg) WPORG=1 ;;
		--svn) SVN_DIR="${2:-}"; WPORG=1; shift ;;
		-h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "Unknown option: $1" >&2; exit 2 ;;
	esac
	shift
done

ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mfail\033[0m  %s\n' "$1" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

command -v php >/dev/null || fail "php is not installed"
command -v zip >/dev/null || fail "zip is not installed"
command -v rsync >/dev/null || fail "rsync is not installed"

# ---------------------------------------------------------------- versions
step "Version"
HEADER_VERSION="$(sed -n 's/^[ *]*Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' "$SRC/$SLUG.php" | head -1)"
CONST_VERSION="$(sed -n "s/.*define( 'WPCYBERSEC_VERSION', '\([^']*\)' ).*/\1/p" "$SRC/$SLUG.php" | head -1)"
STABLE_TAG="$(sed -n 's/^Stable tag:[[:space:]]*\([^[:space:]]*\).*/\1/p' "$SRC/readme.txt" | head -1)"
[ -n "$HEADER_VERSION" ] || fail "No Version: header in $SLUG.php"
[ "$HEADER_VERSION" = "$CONST_VERSION" ] || fail "Header version $HEADER_VERSION differs from WPCYBERSEC_VERSION $CONST_VERSION"
[ "$HEADER_VERSION" = "$STABLE_TAG" ] || fail "Header version $HEADER_VERSION differs from readme.txt Stable tag $STABLE_TAG"
VERSION="$HEADER_VERSION"
ok "$VERSION (plugin header, WPCYBERSEC_VERSION and readme Stable tag match)"
grep -q "^= $VERSION =" "$SRC/readme.txt" && ok "changelog has an entry for $VERSION" || warn "readme.txt changelog has no '= $VERSION =' entry"

# ---------------------------------------------------------------- code checks
step "Code checks"
LINT_FAILED=0
while IFS= read -r -d '' file; do
	php -l "$file" >/dev/null 2>&1 || { php -l "$file" >&2 || true; LINT_FAILED=1; }
done < <(find "$SRC" -name '*.php' -print0)
[ "$LINT_FAILED" = 0 ] || fail "PHP syntax errors (see above)"
ok "PHP syntax ($(find "$SRC" -name '*.php' | wc -l | tr -d ' ') files)"

if command -v node >/dev/null; then
	for js in "$SRC"/assets/js/*.js; do node --check "$js" || fail "JavaScript syntax error in $js"; done
	ok "JavaScript syntax"
else
	warn "node not found: JavaScript syntax not checked"
fi

DASHES="$(perl -ne 'print "$ARGV:$.\n" if /\xe2\x80[\x93\x94]/' $(find "$SRC" -type f \( -name '*.php' -o -name '*.js' -o -name '*.css' -o -name '*.txt' \)) | head -5)"
[ -z "$DASHES" ] || fail "em/en dashes found: $DASHES"
ok "no em or en dashes"

# ---------------------------------------------------------------- WordPress.org checks
if [ "$WPORG" = 1 ]; then
	step "WordPress.org checks"
	README="$SRC/readme.txt"
	grep -q "^=== .* ===$" "$README" || fail "readme.txt must start with '=== Plugin Name ==='"
	CONTRIB="$(sed -n 's/^Contributors:[[:space:]]*//p' "$README" | head -1)"
	case "$CONTRIB" in
		""|*CHANGE_ME*) fail "readme.txt 'Contributors:' must be your WordPress.org username (now: '${CONTRIB:-empty}')" ;;
	esac
	ok "Contributors: $CONTRIB"
	for field in "Requires at least" "Tested up to" "Requires PHP" "License"; do
		grep -q "^$field:" "$README" || fail "readme.txt is missing '$field:'"
	done
	ok "readme headers present"
	TAGS="$(sed -n 's/^Tags:[[:space:]]*//p' "$README" | head -1 | tr ',' '\n' | grep -c .)"
	[ "$TAGS" -le 5 ] && ok "$TAGS tags" || warn "$TAGS tags: only the first 5 are shown on WordPress.org"
	SHORT="$(awk 'f && NF {print; exit} /^License URI:/ {f=1}' "$README")"
	[ "${#SHORT}" -le 150 ] && ok "short description ${#SHORT}/150 characters" || fail "short description is ${#SHORT} characters (max 150)"
	grep -q "^== External services ==" "$README" && ok "external services are documented" || fail "readme.txt needs an '== External services ==' section"
	grep -qi "^ \* License:[[:space:]]*GPL" "$SRC/$SLUG.php" && ok "GPL license header" || fail "plugin header needs a GPL compatible License:"
	case "$SLUG" in wp-*|wordpress-*) warn "slug '$SLUG' starts with 'wp-': the review team may ask for a name that does not start with WP" ;; esac
fi

# ---------------------------------------------------------------- stage
step "Package"
rm -rf "$DIST/build"
mkdir -p "$STAGE"
rsync -a --exclude-from="$ROOT/.distignore" "$SRC/" "$STAGE/"
php "$SRC/bin/build-checksums.php" "--dir=$STAGE" >/dev/null
ok "staged $(find "$STAGE" -type f | wc -l | tr -d ' ') files, checksums.json rebuilt for exactly these files"

ZIP="$DIST/$SLUG-$VERSION.zip"
rm -f "$ZIP" "$ZIP.sha256"
(cd "$DIST/build" && zip -rqX "$ZIP" "$SLUG")
(cd "$DIST" && shasum -a 256 "$(basename "$ZIP")" > "$(basename "$ZIP").sha256")
ok "$(basename "$ZIP") ($(du -h "$ZIP" | cut -f1 | tr -d ' '))"

# ---------------------------------------------------------------- verify the zip
step "Verify zip"
LIST="$(unzip -Z1 "$ZIP")"
TOPS="$(printf '%s\n' "$LIST" | cut -d/ -f1 | sort -u)"
[ "$TOPS" = "$SLUG" ] || fail "zip must contain only the $SLUG/ folder (found: $TOPS)"
ok "single top folder $SLUG/"
for must in "$SLUG/$SLUG.php" "$SLUG/readme.txt" "$SLUG/uninstall.php" "$SLUG/checksums.json" "$SLUG/guard/guard.php"; do
	printf '%s\n' "$LIST" | grep -qx "$must" || fail "missing from zip: $must"
done
ok "required files present"
if printf '%s\n' "$LIST" | grep -E '(^|/)\.DS_Store$|/\.git/|build-checksums\.php$' >/dev/null; then
	fail "zip contains files that should be excluded"
fi
ok "no development files"
CHECK="$(mktemp -d)"
unzip -q "$ZIP" -d "$CHECK"
php -r '
	$dir = $argv[1];
	$map = json_decode( file_get_contents( "$dir/checksums.json" ), true );
	$bad = 0;
	foreach ( $map["files"] as $rel => $sha ) {
		if ( ! is_file( "$dir/$rel" ) || hash_file( "sha256", "$dir/$rel" ) !== $sha ) { echo "  mismatch: $rel\n"; $bad++; }
	}
	exit( $bad ? 1 : 0 );
' "$CHECK/$SLUG" || fail "checksums.json does not match the zipped files"
rm -rf "$CHECK"
ok "every file matches checksums.json"
[ "$(wc -c < "$ZIP")" -lt 10485760 ] && ok "under the 10 MB upload limit" || fail "zip is larger than 10 MB"

# ---------------------------------------------------------------- SVN
if [ -n "$SVN_DIR" ]; then
	step "WordPress.org SVN"
	command -v svn >/dev/null || fail "svn is not installed (brew install subversion)"
	[ -d "$SVN_DIR/.svn" ] || fail "$SVN_DIR is not an SVN checkout (svn co https://plugins.svn.wordpress.org/$SLUG $SVN_DIR)"
	[ ! -e "$SVN_DIR/tags/$VERSION" ] || fail "tags/$VERSION already exists: raise the version first"
	mkdir -p "$SVN_DIR/trunk" "$SVN_DIR/tags" "$SVN_DIR/assets"
	rsync -a --delete --exclude '.svn' "$STAGE/" "$SVN_DIR/trunk/"
	cp -R "$STAGE" "$SVN_DIR/tags/$VERSION"
	if [ -d "$ASSETS" ]; then
		rsync -a --exclude '.DS_Store' "$ASSETS/" "$SVN_DIR/assets/"
		ok "assets copied from wporg-assets/"
	fi
	ok "trunk/ and tags/$VERSION/ updated"
	echo
	echo "  Review and commit:"
	echo "    cd \"$SVN_DIR\""
	echo "    svn status"
	echo "    svn add --force trunk tags/$VERSION assets"
	echo "    svn status | awk '/^!/ {print \$2}' | xargs -r svn rm"
	echo "    svn ci -m \"Release $VERSION\""
fi

step "Done"
echo "  $ZIP"
if [ "$WPORG" = 1 ] && [ -z "$SVN_DIR" ]; then
	echo "  First submission: upload this zip at https://wordpress.org/plugins/developers/add/"
	echo "  After approval:   scripts/build.sh --svn <path to your SVN checkout>"
fi
