# Tech Stack / Version Intelligence

Batch 18 adds a dependency and version evidence layer in front of the existing PoC-in-GitHub reference matcher.

## Goal

The competition workflow should not require manually opening `package.json`, `requirements.txt`, `pom.xml`, lockfiles and Docker files just to copy product names and versions into a search box. NewCyber extracts these signals automatically and reuses them when ranking historical CVE/PoC references.

## Inputs currently recognized

- npm: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`
- Python: `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pyproject.toml`
- Java/JVM: `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`
- Go: `go.mod`, `go.sum`
- Rust: `Cargo.toml`, `Cargo.lock`
- PHP: `composer.json`, `composer.lock`
- Ruby: `Gemfile.lock`
- Containers: `Dockerfile*`, `docker-compose.yml`, `compose.yaml`
- Common service banners: Apache HTTP Server, Tomcat, nginx, OpenSSL, OpenSSH, PHP, Python, Node.js, Spring Boot and Log4j

All file reads are bounded. No package manager is invoked and no dependency is installed.

## Output

For each component NewCyber keeps the ecosystem, normalized package name, exact resolved version when available, declared constraint when only a range is known, source file/evidence, and whether it came from a direct/resolved dependency. Exact package versions also receive Package URL (PURL) identifiers when the ecosystem is supported.

A small high-confidence mapping emits CPE candidates for products whose vendor/product names are known unambiguously (for example Apache Log4j/Tomcat/HTTP Server, OpenSSL and OpenSSH). Unknown products are deliberately left without a guessed CPE.

## PoC-in-GitHub correlation

Component names and exact versions are added to the existing offline keyword query. If a PoC-in-GitHub metadata entry contains both the relevant component vocabulary and the same exact version token, the result is marked `reference-version-match` and its manual verification priority is raised.

This is **not an affected-version decision**. PoC-in-GitHub is a collection of public PoC repository metadata, not an authoritative advisory database. A version appearing in a PoC description may be an example, a tested version or simply repository text. NewCyber therefore never concludes “vulnerable” from this signal alone.

The generated PURL/CPE evidence is intentionally suitable for a later offline advisory layer (for example a pre-downloaded OSV/NVD-compatible dataset) that can perform proper introduced/fixed version range checks.
