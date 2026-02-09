# keycloak-spin

このリポジトリでは keycloak を Rust + WSAM + WASI P2 + spin ベースに移植したものを提供する。

## 構成

- `api`: rest API WASM
- `web`: Vite + React 管理 UI WASM
- `db`: データベースのスキーマ定義と初期化用の WASM
- 'idp': OIDC OP WASM

## CI-CD

WASMは GHCR 経由で Fermyon に配布されます。手順については CI-CD.md （未執筆）を参照してください。

## 利用手順
 
keycloak と同様にデフォルトで main レルムを提供し、 main レルムの Web UI の操作でテナントレルムを追加できます。

### ローカル開発

1. Spin fileserver モジュールを取得

```sh
./scripts/fetch-spin-fileserver.sh
```

2. API ビルド

```sh
cd components/idaas-api
cargo build --release --target wasm32-wasip2
```

`ring` のビルドに `clang`/`lld` が必要です。未導入の場合は `sudo apt-get install -y clang lld` を実行してください。

3. 管理 UI ビルド

```sh
cd web
npm install
npm run build
```

4. Spin 起動

```sh
spin up -f spin.toml
```

`spin.toml` は db/init と api の両コンポーネントを起動します。
ルートの `spin.toml` では、`/db/init` を db 初期化用 WASM に、`/admin/...` を管理 API WASM にルーティングしています。

管理 UI: `http://localhost:3000/admin/`

### 管理 API

`/api/admin` のエンドポイントは `x-admin-token` ヘッダーで保護されています。
デフォルトは `dev-admin-token` です。 `spin.toml` の `admin_api_token` を上書きしてください。

簡易的な CRUD テストは次で実行できます。

```sh
./api/test-realms.sh
```

追加の管理 API テスト:

```sh
./api/test-auth.sh
./api/test-client-scopes.sh
./api/test-groups.sh
```