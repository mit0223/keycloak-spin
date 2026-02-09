# データベース

このディレクトリでは、keyclaok のデータベースのスキーマと初期化用の WASM を提供します。

## 概要

管理対象となるエンティティ・クラスター
Liquibase のソースコードが定義するスキーマは、主に以下の 5 つの主要なデータ領域をカバーしている。

レルム管理（Realm Entities）: レルムの設定、暗号鍵、認証フロー等の定義 。   

ユーザー管理（User Entities）: ユーザー名、ハッシュ化されたパスワード、OTP 秘密鍵、ユーザー属性等の核となる情報 。   

クライアント管理（Client Entities）: Keycloak によって保護されるアプリケーション（OIDC/SAML）のメタデータ、シークレット、プロトコル設定 。   

セッション管理（User Session Entities）: ユーザー・セッションおよびオフライン・トークンの永続化データ 。   

イベント・監査（Event and Audit Entities）: 管理アクションやログイン・イベントのログ記録用テーブル 。

## 初期化用 WASM

DBMS は Sqlite のみをサポートします。データベース名は default を使用します。
db/schema の下にある Liquibase の XML から DDL を生成し、起動時のデータベースの状況に応じてデータベースを初期化します。

## DDL 再生成手順

最新のスキーマをそのまま DDL として出力するため、Hibernate のスキーマエクスポートを使います。Keycloak の model/jpa をビルドしてクラスパスに追加します。

```sh
# リポジトリのルートで実行
unzip -q keycloak-main.zip -d /tmp
cd /tmp/keycloak-main

mvn -pl model/jpa -am -DskipTests -DskipITs -DskipDocs -DskipExamples install

KEYCLOAK_VERSION=$(mvn -q -DforceStdout -pl model/jpa help:evaluate -Dexpression=project.version)

mvn -f /workspaces/keycloak-spin/db/tools/liquibase-exporter/pom.xml \
	-Dkeycloak.version="$KEYCLOAK_VERSION" \
	-q -DskipTests package exec:java \
	-Dexec.mainClass=com.keycloakspin.db.HibernateSchemaExport \
	-Dexec.args="--output /workspaces/keycloak-spin/db/init/sql/schema.sql"
```

## Spin 実行テスト

Spin で WASM を起動し、SQLite の DB が作成されることを確認します。

```sh
# リポジトリのルートで実行
bash db/init/test-spin.sh
```

テスト後に生成物を消す場合は、以下を実行します。

```sh
rm -rf db/init/.spin db/init/target db/init/Cargo.lock
```
