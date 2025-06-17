# Ginger-j

Ginger-j is a lightweight Java library and CLI tool for encrypting and uploading structured data for analysis by the Spice Labs platform.

## ✨ Features

- Uploads either:
  - **ADG directories** (Artifact Dependency Graphs)
  - **Deployment events** in JSON Array format
- Encrypts payloads using a public key derived from your JWT ("Spice Pass")
- Optionally skips upload (`--encrypt-only`) and just outputs the encrypted bundle
- Designed for both **Java embedding** and **CLI use** via Maven

## 🔧 Java Usage

```java
Ginger.builder()
  .jwt("your.jwt.string.or.filepath")
  .adgDir(Path.of("/path/to/adg"))
        .encryptOnly(false)
  .run();
```

## 🚀 CLI Usage

You can run Ginger-j directly using Maven:

```bash
mvn exec:java -Dexec.mainClass=io.spicelabs.ginger.Ginger \
  -Dexec.args="--jwt path/to/spice-pass.jwt --adg path/to/adg-directory"
```

Or for deployment events:

```bash
mvn exec:java -Dexec.mainClass=io.spicelabs.ginger.Ginger \
  -Dexec.args="--jwt path/to/spice-pass.jwt --deployment-events events.json"
```

Optional flags:
- `--uuid` – Override the project UUID if not present in the JWT
- `--encrypt-only` – Only encrypt data without uploading
- `--comment-no-sensitive-info` – Include a non-sensitive comment

## 🪪 Authentication

Ginger expects a valid JWT token for authentication and encryption metadata.
Spice Labs provides these tokens as **Spice Pass** tokens.

The JWT must contain the following claims:
- `x-public-key`: public key in PEM format
- `x-upload-server`: upload endpoint URL
- `x-uuid-project`: project UUID
- `exp`: expiry (must be in the future)

The token can be passed as a raw string or a file path.

## 📦 Maven Dependency

_Coming soon to Maven Central._

## 📜 License

Apache-2.0  
(C) 2025 Spice Labs, Inc. & Contributors