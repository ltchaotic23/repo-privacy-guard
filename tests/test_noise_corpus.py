"""Ordinary, secret-free code and config that must not raise any finding.

43 snippets of the kinds a review found noisy: Kubernetes and Spring config, CSS and JSX,
route declarations, Dockerfiles, package versions, Markdown with units, IDs and numbers.
IP-shaped version numbers use documentation ranges, and the corpus is checked with
report_examples on, so those are treated as public too.
"""

from __future__ import annotations

import unittest

from support import CONFIG, STRICT, pg

CORPUS: list[tuple[str, str]] = [
    # config keys that only describe a secret, or values that are resource names
    ("k8s/tls.yaml", "  secret: my-tls-secret-v1"),
    ("k8s/app.yaml", "  secretKey: db-password-v2"),
    ("k8s/cluster.yaml", "  credentialsSecret: cloud-creds-2026"),
    ("k8s/auth.yaml", "  tokenReviewVersion: v1alpha1"),
    ("k8s/auth.yaml", "  tokenAudience: vault-audience-2026"),
    ("k8s/sync.yaml", "  secretHash: sha256-abc123def456"),
    ("src/main/resources/application.properties", "jwt.token.issuer=auth-service-2026"),
    ("src/main/resources/application.properties", "secret.manager.region=eu-west-2"),
    ("src/main/resources/application.properties", "auth.password.encoding=iso-8859-1"),
    # CSS class names. Some lines below are split into two string literals, so that
    # this file's own source passes the guard; Python joins them back together.
    ("web/buttons.css", ".sk-" "button-primary-v2-large { color: red; }"),
    ("web/Button.jsx", 'const cls = clsx("sk-button-primary-v2-large", active);'),
    # names that describe a secret in code
    ("web/validate.js", 'const password_regex = "^[A-Za-z0-9]{12,64}$";'),
    ("web/oauth.js", 'const token_scope = "read:packages2024";'),
    # route declarations
    ("k8s/ingress.yaml", "      - path: /home/" "dashboard"),
    ("src/main/java/HomeController.java", '    @GetMapping("/home/dashboard")'),
    ("src/main/java/UserController.java", '    @PostMapping("/Users/register")'),
    ("app/urls.py", '    path("/home/dashboard/", views.dashboard, name="dashboard"),'),
    ("app/views.py", '@bp.route("/home/dashboard")'),
    ("web/routes.jsx", '  { path: "/home/dashboard", element: <Dashboard /> },'),
    ("web/Nav.jsx", '        href="/home/' 'dashboard"'),
    ("web/Nav.jsx", '        to="/home/' 'dashboard"'),
    # container home folders
    (".devcontainer/Dockerfile", "WORKDIR /home/vscode"),
    ("Dockerfile", "WORKDIR /home/nonroot"),
    # things shaped like email addresses
    ("package.json", '    "next": "npm:next@14.2.0-canary.beta",'),
    ("web/index.html", '<link rel="icon" href="/favicon@2x.ico">'),
    ("web/index.html", '<link rel="stylesheet" href="/css/theme@dark.css">'),
    ("model/layer.py", "    Y = X@W.real + b"),
    # things shaped like postcodes
    ("docs/hardware.md", "Built on an Apple M1 8GB laptop."),
    ("docs/storage.md", "Each node has an S3 1TB bucket."),
    ("docs/roadmap.md", "Targets for Q1 1st week."),
    ("docs/perf.md", "Latency at p99 1ns better."),
    ("web/style.css", "  border-top: h1 2px solid;"),
    ("web/theme.json", '  "accent": "FA12DE",'),
    # version numbers shaped like IP addresses
    ("charts/web/Chart.yaml", 'appVersion: "198.51.100.10"'),
    ("k8s/web.yaml", "        image: myorg/web:198.51.100.10"),
    ("pom.txt", "com.acme:client:203.0.113.4"),
    ("requirements.txt", "requests >= 203.0.113.1"),
    ("crypto/oids.py", 'COMMON_NAME = "2.5.4.3"'),
    # numbers shaped like phone numbers or IDs
    ("tests/test_ids.py", 'order_id = "0123456789"'),
    ("logs/sample.log", "+2026-11-22 10:30 started"),
    ("src/buffers.py", 'BUFFER_SIZES = "256 512 1024"'),
    ("src/bits.py", "LIMIT = 1152921504606846976  # 2**60"),
    ("src/ids.py", "SAMPLE = 123456789012345678"),
    # Kubernetes/Helm secret reference keys, manifests/lockfiles, Compose defaults, wide JSX and REST routes
    ("k8s/postgres-values.yaml", "  existingSecret: postgres-prod-v1"),
    ("k8s/ingress-values.yaml", "  tlsSecret: wildcard-prod-2026"),
    ("k8s/service-account.yaml", "  pullSecret: ghcr-registry-1"),
    ("k8s/external-secret.yaml", "  secretKey: database-url-v1"),
    ("k8s/bitnami-values.yaml", "  passwordKey: postgres-admin-v1"),
    ("package.json", '    "express-bearer-tok' 'en": "^2.4.0-beta.1",'),
    ("pnpm-lock.yaml", "  '@types/express-bearer-tok" "en': 2.4.0(express@4.19.2)"),
    ("pyproject.toml", 'django-rest-pass' 'wordreset = "^1.4.0rc1"'),
    ("Cargo.toml", 'oauth2-tok' 'en = "0.4.1-alpha.2"'),
    ("src/main/resources/application.yml", "  token-lifespan: PT15M30S"),
    ("docker-compose.yml", '      BROKER_URL: "amqp://guest:' 'guest@rabbitmq:5672/"'),
    ("docker-compose.yml", '      DATABASE_URL: "postgres://postgres:' 'postgres@db:5432/app"'),
    ("src/Button.tsx", '<button className="inline-flex items-center justify-center rounded-md px-4 py-2 text-sm ' "sk-" 'button-primary-v2-2026">'),
    ("src/Card.tsx", 'const cls = cn("flex items-center ' "sk-" 'button-primary-v2-2026");'),
    ("src/Modal.tsx", "className={`" "sk-" "button-primary-v2-2026`}"),
    ("src/Nav.tsx", '<Link className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium" to="/home/' 'dashboard">'),
    ("src/api.ts", 'const res = await fetch("/m/users/profile");'),
    ("src/routes.ts", 'router.get("/i/users/12345", handler);'),
]


def findings(path: str, line: str, cfg: pg.Config) -> list[pg.Finding]:
    return pg.scan_events([pg.LineEvent("", path, 1, line)], cfg)


class NoiseCorpus(unittest.TestCase):
    def test_corpus_size(self) -> None:
        self.assertEqual(len(CORPUS), 61)

    def test_no_findings_with_examples_reported(self) -> None:
        for path, line in CORPUS:
            with self.subTest(path=path, line=line):
                self.assertEqual([f.rule_id for f in findings(path, line, STRICT)], [])

    def test_no_findings_with_the_default_config(self) -> None:
        for path, line in CORPUS:
            with self.subTest(path=path, line=line):
                self.assertEqual([f.rule_id for f in findings(path, line, CONFIG)], [])


if __name__ == "__main__":
    unittest.main()
