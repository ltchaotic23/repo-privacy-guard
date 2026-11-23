"""Every rule in the default config, with values it must catch and values it must not.

The values to catch are reserved example values (see support.py), so they are checked
with STRICT, which reports examples. Rules without reserved examples are also checked
with the default config. A case is a line of text, or (path, text) for rules that only
apply to some files.
"""

from __future__ import annotations

import dataclasses
import unittest

from support import CONFIG, STRICT, file_rule_ids, j, pg, rule_ids, snowflake

Case = str | tuple[str, str]

# rule id -> (must match, must not match)
CONTENT_CASES: dict[str, tuple[list[Case], list[Case]]] = {
    "private-key": (
        [j("-----BEGIN ", "RSA PRIVATE KEY-----"), j("-----BEGIN ", "PRIVATE KEY-----"),
         j("-----BEGIN ", "OPENSSH PRIVATE KEY-----"), j("-----BEGIN ", "ENCRYPTED PRIVATE KEY-----"),
         j("-----BEGIN ", "PGP PRIVATE KEY BLOCK-----")],
        [j("-----BEGIN ", "PUBLIC KEY-----"), j("-----BEGIN ", "CERTIFICATE-----"),
         j("-----BEGIN ", "PGP PUBLIC KEY BLOCK-----"), "paste your private key here"],
    ),
    "aws-access-key-id": (
        [j("AKIA", "IOSFODNN7EXAMPLE"), j('key = "', "ASIA", "IOSFODNN7EXAMPLE", '"')],
        [j("AKIA", "IOSFODNN7EXAMPL"), j("AKIA", "IOSFODNN7EXAMPLE1"), j("X", "AKIA", "IOSFODNN7EXAMPLE"),
         j("akia", "iosfodnn7example"), "AKIA is the prefix"],
    ),
    "aws-secret-access-key": (
        [j("aws_secret_access_key = ", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY"),
         j('AWS_SECRET_ACCESS_KEY: "', "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY", '"'),
         j("aws.secret.access.key=", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY")],
        [j("aws_secret_access_key = ", "${AWS_SECRET}"), j("aws_secret_access_key = ", "short"),
         j("other_secret_key = ", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY")],
    ),
    "github-token": (
        [j("gh", "p_", "A1b2" * 9), j("token: gh", "s_", "Z9y8" * 9),
         j("github", "_pat_", "11EXAMPLE0", "x1" * 25)],
        [j("gh", "p_", "A1b2" * 8), j("xgh", "p_", "A1b2" * 9), "the ghp_ prefix"],
    ),
    "google-api-key": (
        [j("AI", "za", "Sy", "D1" * 16, "E")],
        [j("AI", "za", "Sy", "D1" * 15), j("AI", "za", "Sy", "D1" * 17), "AIza is the prefix"],
    ),
    "google-oauth": (
        [j("GOCSPX", "-", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4"), j("ya29", ".", "EXAMPLE", "x1" * 10)],
        [j("GOCSPX", "-short"), j("ya29", ".", "short"), "ya29 is a prefix"],
    ),
    "slack-token": (
        [j("xox", "b-", "0000000000-0000000000-EXAMPLEexam"), j("xapp", "-1-", "A0000000000-0000000000-example")],
        [j("xox", "b-", "123"), j("xox", "z-", "0000000000-example"), "xoxb- tokens"],
    ),
    "slack-webhook": (
        [j("https://hooks.", "slack.com/services/", "T00000000/B00000000/", "XXXXXXXXXXXXXXXXXXXXXXXX")],
        [j("https://hooks.", "slack.com/services/"), "https://api.slack.com/apps"],
    ),
    "discord-webhook": (
        [j('WEBHOOK = "https://discord.com/api/', "webhooks/", "123456789", "012345678/",
           "FAKE", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab", '"'),
         j("https://discord.com/api/v10/", "webhooks/", "122333444", "4555556666/",
           "FAKE", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-ab")],
        [j("https://discord.com/api/", "webhooks/"),
         j("https://discord.com/api/", "webhooks/", "123456789", "012345678/short")],
    ),
    "telegram-bot-token": (
        [j('BOT_TOKEN = "', "123456789", ":AA", "FAKEabcdefghijklmnopqrstuvwxyz012", '"')],
        [j("12:30", ":AA"), j("123456789", ":AAshort"), j("123456789", ":AB", "FAKEabcdefghijklmnopqrstuvwxyz012")],
    ),
    "pypi-token": (
        [j("pyp", "i-AgEI", "cHlwaS5vcmc", "FAKE", "x1" * 30)],
        [j("pyp", "i-short"), "the pypi-AgEI prefix"],
    ),
    "npmrc-auth": (
        [(".npmrc", j("//registry.npmjs.org/:", "_authToken=", "FAKE0123456789abcdef")),
         ("web/.npmrc", j("_auth", "=", "ZmFrZTpmYWtlcGFzc3dvcmQ=")),
         (".NPMRC", j("//registry.npmjs.org/:", "_authToken=", "FAKE0123456789abcdef"))],
        [(".npmrc", j("//registry.npmjs.org/:", "_authToken=", "${NPM_TOKEN}")),
         (".npmrc", "always-auth=true"),
         ("src/settings.py", j("    _password = ", "FAKE0123456789abcdef"))],
    ),
    "openai-style-key": (
        [j("s", "k-", "proj-", "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8"), j("s", "k-", "ant-api03-", "Ab1Cd2Ef3Gh4Ij5Kl6Mn7"),
         j("s", "k-", "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9")],
        [j("s", "k-", "learn-and-other-words-here"), j("task-", "Ab1Cd2Ef3Gh4Ij5Kl6Mn7"), j("s", "k-", "short1"),
         j('<div class="s', 'k-button-primary-v2-large">')],
    ),
    "stripe-live-key": (
        [j("sk", "_live_", "EXAMPLE0000000000example"), j("rk", "_live_", "EXAMPLE0000000000example")],
        [j("sk", "_test_", "EXAMPLE0000000000example"), j("sk", "_live_", "short")],
    ),
    "gitlab-token": (
        [j("glp", "at-", "Ab1Cd2Ef3Gh4Ij5Kl6Mn")],
        [j("glp", "at-", "short"), "the glpat- prefix"],
    ),
    "huggingface-token": (
        [j("h", "f_", "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh")],
        [j("h", "f_", "short"), j("shel", "f_", "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh")],
    ),
    "npm-token": (
        [j("np", "m_", "A1b2" * 9)],
        [j("np", "m_", "A1b2" * 8), j("np", "m_", "A1b2" * 9, "X")],
    ),
    "discord-bot-token": (
        [j("M", "TIzNDU2Nzg5MDEyMzQ1Njc4", ".", "GaBcDe", ".", "a" * 10, "B1c2D3e4F5g6H7i8J9k0L1m")],
        [j("M", ".short.", "token"), j("x", "MTIzNDU2Nzg5MDEyMzQ1Njc4", ".", "GaBcDe", ".", "a" * 33)],
    ),
    "jwt": (
        [j("eyJ", "hbGciOiJIUzI1NiJ9", ".", "eyJ", "zdWIiOiIxMjM0In0", ".", "abcDEF123_-xyz")],
        [j("eyJ", "hbGciOiJIUzI1NiJ9"), j("eyJ", ".", "eyJ", ".x")],
    ),
    "url-credentials": (
        [j("postgres://", "app:", "s3cretPass", "@db.example.com/app"),
         j("https://", "deploy:", "tok3n", "@git.example.com/repo.git"),
         j('DATABASE_URL = "postgres://', "app:", "Tr0ub4dor", "%40x", '@db.internal:5432/app"'),
         j('REDIS_URL = "redis://', ":", "FakeRedisPassw0rd99", '@cache.internal:6379/0"')],
        [j("postgres://", "app:", "password", "@db.internal/app"),
         j("postgres://", "app:", "${DB_PASSWORD}", "@db/app"),
         j("DATABASE_URL=postgres://", "postgres:", "postgres", "@localhost:5432/dev"),
         j("redis://", ":", "devpass123", "@127.0.0.1:6379"),
         "https://example.com/path?q=1", j("ssh://", "git", "@example.com/repo.git")],
    ),
    "secret-assignment": (
        [j('password = "', "Tr0ub4dor", "AndMore", '"'), j('"api_key": "', "abc123def456ghi", '"'),
         j("client_secret: '", "a1b2c3d4e5f6g7h8", "'"), j('DB_PASSWORD="', "Sup3rS3cretValue", '"'),
         j('password = "', "Tr0ub4dor$FAKE2026x", '"'),
         j('    "api_key = \\"', "Ab1Cd2Ef3Gh4FAKE9", '\\"\\n",'),
         j('api_key_prod = "', "Ab1Cd2Ef3Gh4Ij5", '"'), j('password = "', "aB3<x9!mK2pQ8z", '"'),
         j('password = "', "$SuperSecret2026!", '"'), j("const password = `", "Tr0ub4dorAndMore1", "`;"),
         j('password = b"', "Tr0ub4dorAndMore1", '"'), j("token = r'", "Ab1Cd2Ef3Gh4Ij5Kl", "'"),
         j('secretValue: "', "Ab1Cd2Ef3Gh4Ij5", '"'), j('apiKeyLive = "', "Ab1Cd2Ef3Gh4Ij5", '"')],
        [j('password = "', "changeme12345", '"'), j('token_url = "', "https://oauth2.example.com/token", '"'),
         j('api_key = "', "${{ secrets.API_KEY }}", '"'), j('max_tokens = "', "40961234abcd", '"'),
         j('secret = "', "abcdefghijklmnop", '"'), j('password = "', "short1", '"'),
         j('password = "', "${DB_PASSWORD}2026", '"'), j('password = "', "%(db_password)s2026", '"'),
         j('secret_name = "', "prod-db-credentials-v2", '"'), j('token_type = "', "Bearer2026abc", '"'),
         j('password = "', "$DB_PASSWORD2", '"'), j('password = "', "<db-password-2>", '"'),
         j('tokenizer = "', "bert-base-uncased-v2", '"'), j('const password_regex = "', "^[A-Za-z0-9]{12,64}$", '"'),
         j('const token_scope = "', "read:packages2024", '"')],
    ),
    "dockerfile-secret": (
        [("Dockerfile", j("ENV API_KEY ", "Ab1Cd2Ef3Gh4Ij5Kl")), ("Dockerfile", j("ENV api_key=", "Ab1Cd2Ef3Gh4Ij5Kl")),
         ("docker/web.Dockerfile", j("ENV DB_PASSWORD ", "Tr0ub4dorAndMore1")),
         ("Containerfile", j("arg db_password=", "Tr0ub4dorAndMore1")),
         ("Dockerfile", j("# ENV API_KEY ", "Ab1Cd2Ef3Gh4Ij5Kl")), ("Dockerfile", j('ENV API_KEY "', "Ab1Cd2Ef3Gh4Ij5Kl", '"'))],
        [("Dockerfile", "ENV API_KEY_FILE /run/secrets/api_key"), ("Dockerfile", j("ENV TOKEN ", "${TOKEN}")),
         ("src/app.py", j("ENV API_KEY ", "Ab1Cd2Ef3Gh4Ij5Kl")), ("Dockerfile", "ENV NODE_ENV production"),
         ("Dockerfile", "ENV SECRET_REGION eu-west-2"), ("Dockerfile", "ENV TOKEN_ISSUER auth-service-2026"),
         ("Dockerfile", "ARG TOKEN_VERSION v1alpha1"), ("Dockerfile", "ENV token_name my-token-name-2026"),
         ("Dockerfile", "ENV TOKEN_TTL 3600s-default")],
    ),
    "xml-secret": (
        [j("<password>", "Tr0ub4dorFAKE2026", "</password>"), j("  <api-key>", "Ab1Cd2Ef3Gh4Ij5", "</api-key>")],
        ["<password></password>", j("<password>", "${DB_PASSWORD}", "</password>"),
         "<passwordPolicy>strict-2026</passwordPolicy>"],
    ),
    "env-style-secret": (
        [j("API_KEY=", "abc123def456ghi789"), j("export GITHUB_TOKEN=", "Ab1Cd2Ef3Gh4Ij5"),
         j("DB_PASSWORD = ", "Tr0ub4dorAndMore"), j("# OLD_SECRET=", "a1b2c3d4e5f6g7h8"),
         j("      - DB_PASSWORD=", "MyFakeProdPassw0rd99"), j("DB_PASSWORD=", "Tr0ub4dor#99xyz"),
         j("ENV API_KEY=", "Ab1Cd2Ef3Gh4Ij5Kl")],
        [j("API_KEY=", "${API_KEY}"), j("API_KEY=", "your-api-key-here-123"),
         j("api_key=", "abc123def456ghi789"), j("TOKEN_URL=", "https://auth.example.com/t0ken")],
    ),
    "config-secret": (
        [("config/app.yaml", j("  api_key: ", "Abc123Def456FAKE789xyz")),
         ("app/signing.gradle.properties", j("storePassword=", "FakeStorePassw0rd123")),
         ("settings.ini", j("secret_key = ", "a1b2c3d4e5f6g7h8")),
         ("docker-compose.yml", j("      - DB_PASSWORD=", "MyFakeProdPassw0rd99")),
         ("application.properties", j("spring.datasource.password = ", "SuperFake#99"))],
        [("config/app.yaml", j("  api_key: ", "${API_KEY}")),
         ("config/app.yaml", j("  token_url: ", "https://auth.example.com/t0ken")),
         ("config/app.yaml", j("  password: ", "changeme12345")),
         ("src/app.py", j("api_key = ", "config.api_key_v2")),
         j("  api_key: ", "Abc123Def456FAKE789xyz"),
         ("k8s/deploy.yaml", "      secretName: tls-cert-2026"),
         ("k8s/deploy.yaml", "          secretKeyRef: app-secret-v1"),
         ("docker-compose.yml", "      POSTGRES_PASSWORD_FILE: /run/secrets/db_pass_1"),
         ("src/main/resources/application.yml", "password_encoder: argon2id"),
         ("config/app.yaml", "credentials_path: /etc/app/v1/creds"),
         ("src/main/resources/application.properties", "spring.security.oauth2.token.endpoint=/oauth2/token2"),
         ("settings.toml", 'api_key_header = "X-Api-Key-2"'),
         ("config/app.yaml", j("# api_key: ", "FakeSecret123456"))],
    ),
    "home-path-windows": (
        [j("C:", "\\Users\\", "exampleuser", "\\Documents"), j("c:", "/Users/", "exampleuser/app"),
         j('"C:', "\\\\Users\\\\", 'exampleuser\\\\AppData"'), j("/mnt/c", "/Users/", "exampleuser"),
         j("cd /c", "/Users/", "exampleuser/Projects/app"), j("file:///C", "%3A/Users/", "exampleuser/doc.txt"),
         j("sdk.dir=C\\:\\\\Users\\\\", "exampleuser", "\\\\AppData"), j("/cygdrive/c", "/Users/", "exampleuser/x"),
         j("See C:", "\\Users\\", "exampleuser.")],
        [j("C:", "\\Users\\", "<name>\\Documents"), j("C:", "\\Users\\", "Public\\Documents"),
         j("C:", "\\Users\\", "%USERNAME%"), j("C:", "\\Users\\", "$env:USERNAME"),
         j("C:", "\\Program Files\\", "App"), j("D:", "\\Projects\\", "exampleuser"),
         j("https://example.org/c", "/Users/", "exampleuser"), j("(C:", "\\Users\\", "username)"),
         j("See C:", "\\Users\\", "Public.")],
    ),
    "home-path-linux": (
        [j("/ho", "me/", "exampleuser/.ssh/config"), j("cd ", "/home/", "example-user"),
         j('open("/home/', "exampleuser", '/notes.txt")'), j("git fetch /home/", "exampleuser", "/repo"),
         j("sftp> get /home/", "exampleuser", "/file.txt"), j("Fetch it from /home/", "exampleuser", "."),
         j('cache.get("/home/', "exampleuser", '/secret.txt")'), j('src = "/home/', "exampleuser", '/data"'),
         j('to = "/home/', "exampleuser", '/x"'), j('dirs.push("/home/', "exampleuser", '")')],
        [j("/home/", "runner/work"), j("/home/", "user/app"),
         j("https://example.com", "/home/", "exampleuser"), j("/home/", "${USER}"), "/homepage",
         'router.get("/home/dashboard", handler);', '<a href="/home/index.html">',
         '<Link to="/home/settings">', 'app.use("/home/api", handler)', "See /home/user.",
         j("      - path: /home/", "dashboard"), '    @GetMapping("/home/dashboard")',
         '    path("/home/dashboard/", views.dashboard),', '@bp.route("/home/dashboard")',
         j('  { path: "/home/', 'dashboard", element: <Dashboard /> },'), j('        href="/home/', 'dashboard"'),
         j('        to="/home/', 'dashboard"'), ("Dockerfile", "WORKDIR /home/vscode"), j("WORKDIR /home/", "nonroot")],
    ),
    "home-path-macos": (
        [j("/Us", "ers/", "exampleuser/Library"), j("open '/Users/", "example", "/Desktop'"),
         j("git fetch /Us", "ers/", "exampleuser/repo")],
        [j("/Users/", "Shared/file"), j("/Users/", "<name>/x"),
         j("https://api.example.com", "/Users/", "123"), j("/Users/", "$USER"),
         'fetch("/Users/12345/profile")', j("See /Users/", "Shared.")],
    ),
    "email": (
        [j("exampleuser", "@", "example.com"), j("Contact: ", "someone", "@", "example.org"),
         j("first.last+tag", "@", "sub.example.net"), j("mailto:", "someone", "@", "example.com"),
         j("//", "someone", "@", "example.com"), j("https://app.example.org/users/", "someone", "@", "example.net")],
        [j("12345678+someone", "@", "users.noreply.github.com"), j("git", "@", "github.com:owner/repo.git"),
         j("noreply", "@", "github.com"), j("logo", "@", "2x.png"),
         j("user", "@", "localhost"), j("package", "@", "1.2.3"), "@decorator.name",
         j("Signed-off-by: dependabot[bot] <", "support", "@", "github.com>"),
         "Run: systemctl enable myapp@prod.service", "uses: org/action@release.main",
         j("postgres://", "app:", "Tr0ub4dor", "@db.example.com/app"),
         '"next": "npm:next@14.2.0-canary.beta"', '<link href="/favicon@2x.ico">',
         '<link href="/css/theme@dark.css">', "Y = X@W.real + b"],
    ),
    "phone-international": (
        [j("+44 7700 ", "900123"), j("+44 (0)7700 ", "900456"), j("+44", "7700900789"),
         j("+44 20 ", "7946 0123"), j("+1 (202) ", "555-0143")],
        [j("+1 ", "234"), j("x+", "447700900123"), j("+44 7700 ", "900xxx"), j("+0", "123456789012"),
         j("+44--", "7700--900123"), "lat = +51.50735091", "offset = +1000000000",
         "+2026-11-22 10:30 started"],
    ),
    "phone-uk": (
        [j("07700 ", "900123"), j("(07700) ", "900456"), j("07700 ", "900 789"), j("0", "7700900321"),
         j("020 ", "7946 0123"), j("Call us on 07700-", "900123."), j("020-7946-", "0123")],
        [j("01/02/", "2026"), j("0.", "123456789"), j("0", "123"), j("v0", "7700900123"),
         j("0", "77009001234567"), j("2026-01-", "15"), 'order_id = "0123456789"'],
    ),
    "phone-north-america": (
        [j("(202) ", "555-0143"), j("202-", "555-0172"), j("202.", "555.0199")],
        [j("123-", "456-7890"), j("202", "5550143"), j("2026-", "11-22"), j('"256 ', '512 1024"'),
         j("+1 (202) ", "555-0143"), j("+1 202 ", "555 0143")],
    ),
    "public-ipv4": (
        [j("192.0", ".2.10"), j("connect to ", "198.51", ".100.20", "."), j("host=", "203.0", ".113.7"),
         j("ssh deploy@", "203.0", ".113.7"), j("scp notes.txt user@", "198.51", ".100.7", ":/tmp/"),
         j("if ip == ", "198.51", ".100.7:")],
        [j("192.168", ".1.10"), j("10.0", ".0.5"), j("127.0", ".0.1"), j("1.2.3", ".4.5"),
         j("v1.26", ".4.0"), j("256.1", ".1.1"), j("224.0", ".0.1"), j("100.64", ".0.1"), j("0.0", ".0.0"),
         j('  "version": "', "198.51", '.100.20",'), j('COMMON_NAME_OID = "', "203.0", '.113.3"'),
         j("requests==", "198.51", ".100.1"), j("numpy>=", "203.0", ".113.0"),
         j("<AssemblyVersion>", "198.51", ".100.7</AssemblyVersion>"), j('appVersion: "', "198.51", '.100.10"'),
         j("image: myorg/web:", "198.51", ".100.10"), j("com.acme:client:", "203.0", ".113.4"),
         j("requests >= ", "203.0", ".113.1"), 'COMMON_NAME = "2.5.4.3"'],
    ),
    "public-ipv6": (
        [j("2001:db8", "::1"), j("dns ", "2001:db8:", "0:1::53", ".")],
        [j("::", "1"), j("fe80::", "1"), j("fd00::", "1"), j("12:30", ":45"),
         j("aa:bb:cc", ":dd:ee:ff"), j("std", "::vector")],
    ),
    "uk-postcode": (
        [j("ZZ99 ", "9ZZ"), j("ZZ99", "9ZZ"), j("Postcode: ", "ZZ99", " 9ZZ."), j("Our postcode is zz99 ", "9zz."),
         j("Zz99 ", "9zZ"), j("ZZ99", " ", "9ZZ")],
        [j("ZZ99 ", "9CI"), j("XZZ99 ", "9ZZ"), j("zz99", "9zz"), "CR2032 battery", "AB12",
         ".banner { color: #FA12DE; }", "border: 1px solid #AB12EF;", j("QA1 ", "1AB"), j("AZ1 ", "1AB"),
         j("VE1 ", "1AB"), "Built on an Apple M1 8GB laptop.", "Each node has an S3 1TB bucket.",
         "Targets for Q1 1st week.", "Latency at p99 1ns better.", "border-top: h1 2px solid;",
         '"accent": "FA12DE",'],
    ),
    "discord-id": (
        [snowflake(2020), j("user_id = ", snowflake(2024))],
        ["1234567890123456", str(10**19 + 7), j("0.", snowflake(2020)), j("abc", snowflake(2020)),
         "WEI_PER_ETH = 1000000000000000000", "STARTED_NS = 1732280000000000000",
         "LIMIT = 1152921504606846976", "SAMPLE = 123456789012345678"],
    ),
}

FILE_CASES: dict[str, tuple[list[str], list[str]]] = {
    "env-file": ([".env", "config/.env.production", ".envrc", ".ENV", "config/.Env.local"],
                 [".env.example", "config/.env.sample", "docs/env.md", "src/environment.py",
                  ".env.development.example", "config/.ENV.local.sample"]),
    "key-file": (["id_rsa", "secrets/server.pem", "deploy/key.p12", "keys/id_ed25519", "vault.kdbx"],
                 ["id_rsa.pub", "keyboard.py", "src/keys.py", "monkey.txt"]),
    "certificate-file": (["certs/site.crt", "ca.cer"], ["src/cert_utils.py", "docs/certificates.md"]),
    "terraform-state": (["terraform.tfstate", "infra/terraform.tfstate.backup"],
                        ["main.tf", "variables.tf", "tfstate.md"]),
    "terraform-vars": (["terraform.tfvars", "infra/prod.auto.tfvars", "vars.tfvars.json"],
                       ["terraform.tfvars.example", "docs/tfvars.md", "variables.tf"]),
    "credentials-file": (["credentials.json", "client_secret_123.apps.json", ".netrc", ".git-credentials"],
                         ["docs/credentials.md", "src/credentials_helper.py"]),
    "signing-properties": (["keystore.properties", "android/app/signing.properties"],
                           ["gradle.properties", "keystore.properties.example"]),
}


def split(case: Case) -> tuple[str | None, str]:
    return case if isinstance(case, tuple) else (None, case)


def uses_examples(rule_id: str) -> bool:
    rule = next(r for r in CONFIG.rules if r.id == rule_id)
    return bool(rule.examples) or rule.check == "public_ip"


class EveryRuleIsTested(unittest.TestCase):
    def test_every_content_rule_has_cases(self) -> None:
        ids = {rule.id for rule in CONFIG.rules}
        self.assertEqual(ids, set(CONTENT_CASES), "add cases for new rules, remove old ones")
        for rule_id, (good, bad) in CONTENT_CASES.items():
            self.assertTrue(good and bad, rule_id)

    def test_every_file_rule_has_cases(self) -> None:
        self.assertEqual({rule.id for rule in CONFIG.file_rules}, set(FILE_CASES))


class ContentRules(unittest.TestCase):
    def test_true_positives(self) -> None:
        for rule_id, (good, _) in CONTENT_CASES.items():
            configs = [STRICT] if uses_examples(rule_id) else [STRICT, CONFIG]
            for index, case in enumerate(good):
                path, text = split(case)
                for cfg in configs:
                    with self.subTest(rule=rule_id, case=index, strict=cfg.report_examples):
                        self.assertIn(rule_id, rule_ids(text, cfg, path))

    def test_false_positives(self) -> None:
        for rule_id, (_, bad) in CONTENT_CASES.items():
            for index, case in enumerate(bad):
                path, text = split(case)
                for cfg in (STRICT, CONFIG):
                    with self.subTest(rule=rule_id, case=index, strict=cfg.report_examples):
                        self.assertNotIn(rule_id, rule_ids(text, cfg, path))

    def test_ordinary_code_is_quiet(self) -> None:
        lines = [
            "def main(argv: list[str] | None = None) -> int:",
            "    return 0",
            "import os, sys",
            "version = '1.2.3'",
            "colour: #ff8800;",
            "for (let i = 0; i < 10; i++) {}",
            "SELECT id, name FROM users WHERE id = 42;",
            "git clone https://github.com/owner/repo.git",
            "Copyright (c) 2026 Example Ltd",
            "commit 3d3c42e5aac5ba805825da76410c181273ba90b1",
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(rule_ids(line, STRICT), set())

    def test_carriage_return_does_not_hide_anchored_rules(self) -> None:
        # A file with old Mac line endings reaches the scanner as one long line.
        event = pg.LineEvent("", "settings.env", 1, j("DEBUG=1\r", "API_KEY=", "abc123def456ghi789\r"))
        found = {f.rule_id for f in pg.scan_events([event], STRICT)}
        self.assertIn("env-style-secret", found)


class TrailingPunctuation(unittest.TestCase):
    """Placeholders and examples at the end of a sentence or in brackets pass by default."""

    def test_default_config_ignores_them(self) -> None:
        for line in (j("See C:", "\\Users\\", "exampleuser."), j("(C:", "\\Users\\", "username)"),
                     "See /home/user.", j("See C:", "\\Users\\", "Public."), j("See /Users/", "Shared."),
                     j("Run it as /home/", "example,", " then stop.")):
            with self.subTest(line=line):
                self.assertEqual(rule_ids(line, CONFIG), set())


class Severity(unittest.TestCase):
    NOISY = {"discord-id", "uk-postcode", "public-ipv4", "public-ipv6", "phone-international",
             "phone-uk", "phone-north-america"}

    def test_noisy_personal_rules_warn_by_default(self) -> None:
        warn = {r.id for r in CONFIG.rules if pg.severity_of(r, CONFIG) == "warn"}
        self.assertEqual(warn, self.NOISY)

    def test_secrets_always_block(self) -> None:
        for rule in CONFIG.rules:
            if rule.category == "secret":
                with self.subTest(rule=rule.id):
                    self.assertEqual(rule.severity, "block")

    def test_strict_makes_every_rule_block(self) -> None:
        strict = dataclasses.replace(CONFIG, strict=True)
        self.assertEqual({pg.severity_of(r, strict) for r in strict.rules}, {"block"})


class ReservedExamples(unittest.TestCase):
    """Sample data written with reserved values passes by default, and is reported on request."""

    CASES = {
        "email": j("exampleuser", "@", "example.com"),
        "home-path-windows": j("C:", "\\Users\\", "exampleuser"),
        "home-path-linux": j("/home/", "example"),
        "phone-international": j("+44 7700 ", "900123"),
        "phone-uk": j("020 ", "7946 0999"),
        "phone-north-america": j("(202) ", "555-0100"),
        "public-ipv4": j("203.0", ".113.7"),
        "public-ipv6": j("2001:db8", "::1"),
        "uk-postcode": j("ZZ99 ", "9ZZ"),
    }

    def test_ignored_by_default(self) -> None:
        for rule_id, text in self.CASES.items():
            with self.subTest(rule=rule_id):
                self.assertNotIn(rule_id, rule_ids(text, CONFIG))

    def test_reported_with_report_examples(self) -> None:
        for rule_id, text in self.CASES.items():
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rule_ids(text, STRICT))

    def test_example_patterns_are_anchored(self) -> None:
        # A reserved number with extra digits on the end is not an example any more.
        patterns = [p for r in CONFIG.rules if r.id == "phone-uk" for p in r.examples]
        self.assertTrue(any(p.search(j("07700900", "123")) for p in patterns))
        self.assertFalse(any(p.search(j("07700900", "1234")) for p in patterns))


class PublicAddresses(unittest.TestCase):
    """The public-IP check with the default config.

    Needs addresses that really are public. These are AS112 addresses: reserved by IANA for
    a shared public DNS sink service (RFC 7534, RFC 7535), not anyone's machine.
    """

    def test_public_addresses_are_public(self) -> None:
        for text in (j("192.31", ".196.1"), j("192.175", ".48.6"), j("2620:4f", ":8000::1")):
            with self.subTest(address=text):
                self.assertTrue(pg.CHECKS["public_ip"](text, False))
                self.assertTrue(rule_ids(text, CONFIG) & {"public-ipv4", "public-ipv6"})

    def test_non_public_addresses(self) -> None:
        for text in ("192.0.2.1", "10.1.2.3", "172.16.0.1", "127.0.0.1", "169.254.1.1",
                     "100.64.0.1", "224.0.0.1", "240.0.0.1", "2001:db8::1", "fe80::1", "::1"):
            with self.subTest(address=text):
                self.assertFalse(pg.CHECKS["public_ip"](text, False))


class FileRules(unittest.TestCase):
    def test_true_positives(self) -> None:
        for rule_id, (good, _) in FILE_CASES.items():
            for path in good:
                with self.subTest(rule=rule_id, path=path):
                    self.assertIn(rule_id, file_rule_ids(path))

    def test_false_positives(self) -> None:
        for rule_id, (_, bad) in FILE_CASES.items():
            for path in bad:
                with self.subTest(rule=rule_id, path=path):
                    self.assertNotIn(rule_id, file_rule_ids(path))


if __name__ == "__main__":
    unittest.main()
