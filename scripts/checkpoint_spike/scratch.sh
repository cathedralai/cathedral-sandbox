#!/bin/bash
# Shared scratch-path guards for checkpoint spike scripts (AB#672).
# Restrict NAME to a simple basename and keep cleanup targets under RUNS/IMGROOT.

ckspike_require_name() {
  local name=$1
  if [[ -z "$name" || "$name" == "." || "$name" == ".." || "$name" == */* || "$name" == */ ]]; then
    echo "ckspike: NAME must be a simple basename (got: ${name:-empty})" >&2
    exit 2
  fi
}

# Resolve path and assert it stays under root (both must exist or be creatable under root).
ckspike_under_root() {
  local root=$1 path=$2 label=$3
  local root_abs path_abs
  mkdir -p "$root"
  root_abs=$(cd "$root" && pwd -P)
  mkdir -p "$(dirname "$path")"
  # path may not exist yet; resolve parent then append basename
  local parent base
  parent=$(cd "$(dirname "$path")" && pwd -P)
  base=$(basename "$path")
  path_abs="$parent/$base"
  case "$path_abs" in
    "$root_abs"|"$root_abs"/*) ;;
    *)
      echo "ckspike: $label escapes scratch root $root_abs (resolved $path_abs)" >&2
      exit 2
      ;;
  esac
  printf '%s\n' "$path_abs"
}
