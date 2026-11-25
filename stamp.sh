#!/bin/sh
# Run before each deploy: gives the build a new stamp so open phones reload to it.
# Only the one line that DEFINES the build number may change; nothing else in the page.
v=$(date +%s)
sed -i "s/^const BUILD=\"[0-9A-Z_]*\";\$/const BUILD=\"$v\";/" public/index.html
n=$(grep -c "^const BUILD=\"$v\";\$" public/index.html)
[ "$n" = "1" ] || { echo "stamp failed: expected exactly one BUILD line, found $n" >&2; exit 1; }
printf '{"v":"%s"}\n' "$v" > public/version.json
