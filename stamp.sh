#!/bin/sh
# Run before each deploy: gives the build a new stamp so open phones reload to it.
v=$(date +%s)
sed -i "s/const BUILD=\"[^\"]*\"/const BUILD=\"$v\"/" public/index.html
printf '{"v":"%s"}\n' "$v" > public/version.json
