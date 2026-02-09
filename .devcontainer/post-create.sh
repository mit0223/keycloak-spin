#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y clang lld nodejs npm default-jdk-headless maven unzip

mkdir -p .spin
cd .spin

curl -fsSL https://developer.fermyon.com/downloads/install.sh | bash
sudo mv spin /usr/local/bin/

rustup target add wasm32-wasip2


