# header-guard

> サイトのHTTPセキュリティヘッダを1コマンドで診断し、指摘ごとに具体的な修正方法を示すツール。

[English README](README.md)

`header-guard` は指定したURL（`localhost` も可）のレスポンスヘッダを調べ、
CSP・HSTS・Cookie属性・CORS・クリックジャッキング対策などの設定ミスを検出します。
**何が問題か・なぜ危険か・どのヘッダを足せばよいか** をまとめて表示します。

- **依存パッケージなし**：Node.js 12以上だけで動きます
- **CIで使いやすい**：問題があれば終了コード1を返し、`--json` 出力や `--ignore`（許容するリスクの除外）にも対応
- **受動的な診断のみ**：通常の `GET` を1回送るだけ（リダイレクトは追跡）。攻撃ペイロードは送りません
- **ライブラリとしても使える**：`audit(headers)` は純粋関数なので、結合テストに組み込めます

## 使い方

```sh
npx header-guard http://localhost:3000
npx header-guard https://staging.example.com --fail-on medium
curl -sI https://example.com | npx header-guard - --https   # 標準入力のヘッダを診断
```

主なオプション：

| オプション | 説明 |
| --- | --- |
| `--fail-on <level>` | この重要度以上の指摘があれば終了コード1（既定は `high`。`none` で常に0） |
| `--min-severity <level>` | 指定より低い重要度の指摘を表示しない |
| `--ignore <ids>` | 除外する指摘IDをカンマ区切りで指定 |
| `--json` | JSON形式で出力 |
| `-H "Name: value"` | リクエストヘッダを追加（ログイン後のページを診断するときのCookieなど） |
| `--insecure` | 自己署名証明書を許可（ローカル開発用） |

終了コード：`0` 合格 / `1` 基準以上の指摘あり / `2` 引数またはネットワークのエラー

### ライブラリとして使う

```js
const { audit } = require('header-guard');

const res = await fetch('http://localhost:3000/');
const findings = audit(res.headers, { url: res.url, minSeverity: 'medium' });
assert.deepStrictEqual(findings, []);
```

チェック項目の一覧は [README.md](README.md#checks) を参照してください。

## 注意

ヘッダを読むだけのツールなので、脆弱性診断（ペネトレーションテスト）の代わりにはなりません。
**自分が管理しているサイト、または許可を得たサイトに対してのみ使ってください。**

## ライセンス

MIT
