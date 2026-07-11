#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

mvn -q -f "$project_dir/pom.xml" -DskipTests package

has_request=false
for argument in "$@"; do
  case "$argument" in
    --param|--param=*|--request-json) has_request=true ;;
  esac
done

if $has_request; then
  exec java -jar "$project_dir/target/libsigner-unidbg-1.0-SNAPSHOT.jar" "$@"
else
  exec java -jar "$project_dir/target/libsigner-unidbg-1.0-SNAPSHOT.jar" \
    --request-json "$project_dir/src/test/resources/request-sandbox.json" "$@"
fi

