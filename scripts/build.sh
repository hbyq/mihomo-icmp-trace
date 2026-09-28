#!/usr/bin/env bash
set -euo pipefail

# Build only pinned public upstream commits and the adjacent reviewed patches.
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${project_dir}/work"
dist_dir="${project_dir}/dist"
mkdir -p "$build_dir" "$dist_dir"
for repo in mihomo sing-tun; do
  if [[ -e "$build_dir/$repo" ]]; then
    echo "Refusing to overwrite existing build directory: $build_dir/$repo" >&2
    exit 1
  fi
done

fetch_source() {
  local repo="$1" revision="$2"
  local archive="$build_dir/$repo.tar.gz"
  curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
    "https://codeload.github.com/MetaCubeX/$repo/tar.gz/$revision" -o "$archive"
  mkdir "$build_dir/$repo"
  tar -xzf "$archive" --strip-components=1 -C "$build_dir/$repo"
  git -C "$build_dir/$repo" apply --check "$project_dir/patches/$repo.patch"
  git -C "$build_dir/$repo" apply "$project_dir/patches/$repo.patch"
}

fetch_source mihomo ab405bad5beeeac8b003bb01f60f134f6df54471
fetch_source sing-tun b50ae28a1409c7bce8e96e6c6966cf57d8ace754

cd "$build_dir/mihomo"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags with_gvisor -trimpath \
  -ldflags '-s -w -X github.com/metacubex/mihomo/constant.Version=v1.19.31-icmp-trace-exp1' \
  -o "$dist_dir/mihomo-windows-amd64-icmp-trace-exp1.exe" .
echo "Built: $dist_dir/mihomo-windows-amd64-icmp-trace-exp1.exe"
