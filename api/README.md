# admin-api

Spin WASM component stub for the Keycloak Admin REST API.

## Build

```sh
cargo build --target wasm32-wasip2 --release
```

## Run (standalone)

```sh
spin up
```

## Test

Start the component (or the root `spin.toml`), then run:

```sh
./test-realms.sh
./test-auth.sh
./test-client-scopes.sh
./test-clients.sh
./test-components.sh
./test-events.sh
./test-groups.sh
```

Optional environment variables:

- `BASE_URL` (default `http://127.0.0.1:3000`)
- `REALM` (default `demo`)
- `SPIN_UP` (default `0`)
- `SPIN_BUILD` (default `0`, when `SPIN_UP=1` to rebuild WASM)

## Notes

- The component opens the default SQLite database on every request.
- All routes are handled via the "/..." catch-all route in the Spin manifest.
