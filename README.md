# Ginger-j

[![Maven Central](https://img.shields.io/maven-central/v/io.spicelabs/ginger-j?label=Maven%20Central)](https://central.sonatype.com/artifact/io.spicelabs/ginger-j)
[![GitHub Release](https://img.shields.io/github/v/release/spice-labs-inc/ginger-j?label=GitHub%20Release)](https://github.com/spice-labs-inc/ginger-j/releases)
[![GitHub Package](https://img.shields.io/badge/GitHub-Packages-blue?logo=github)](https://github.com/spice-labs-inc/ginger-j/packages/)

**Ginger-j** is a lightweight Java library and CLI for encrypting and uploading structured data to the Spice Labs platform.

---

## ✨ Features

- 🔐 End-to-end encryption using your **Spice Pass** (JWT-based auth)
- 📁 Uploads:
  - **Artifact Dependency Graphs (ADG)**
  - **Deployment events** (JSON array)
- 🛠️ CLI flags for encryption-only mode and custom metadata
- 🧩 Usable as a **Java library** or **CLI via Maven**

---

## 📦 Getting Started

### Add to your Maven project:

If using [Maven Central](https://central.sonatype.com/artifact/io.spicelabs/ginger-j):

```xml
<dependency>
  <groupId>io.spicelabs</groupId>
  <artifactId>ginger-j</artifactId>
  <version>0.1.0</version>
</dependency>
```

If using GitHub Packages (only needed if not yet in Maven Central):

```xml
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/spice-labs-inc/ginger-j</url>
  </repository>
</repositories>
```

---

## 🚀 CLI Usage

You can run directly with Maven:

```bash
mvn clean compile
mvn exec:java -Dexec.mainClass=io.spicelabs.ginger.Ginger \
  -Dexec.args="--jwt path/to/spice-pass.jwt --adg path/to/adg-directory"
```

Or for deployment events:

```bash
mvn clean compile
mvn exec:java -Dexec.mainClass=io.spicelabs.ginger.Ginger \
  -Dexec.args="--jwt path/to/spice-pass.jwt --deployment-events events.json"
```

### Optional CLI flags:

- `--uuid` – Override project UUID from JWT
- `--encrypt-only` – Only encrypt; don't upload
- `--comment-no-sensitive-info` – Add a human-readable comment

---

## 🧑‍💻 Java Usage

Embed Ginger in your own Java code:

```java
Ginger.builder()
  .jwt("your.jwt.string.or.filepath")
  .adgDir(Path.of("/path/to/adg"))
  .encryptOnly(false)
  .run();
```

---

## 🪪 Authentication

You must supply a valid **Spice Pass** (JWT), either as a file path or raw string.

Required JWT claims:

| Claim             | Purpose                            |
|------------------|-------------------------------------|
| `x-public-key`    | Public key used to encrypt payload |
| `x-upload-server` | URL to POST the encrypted bundle   |
| `x-uuid-project`  | UUID for the target project        |
| `exp`             | Expiration (must be in future)     |

---

## 🛠️ Releasing Ginger-j

### Manual release steps for maintainers:

1. **Create a new GitHub release**  
   Tag the release with a semantic version like `v0.1.0`. This triggers the GitHub Actions workflow to build and publish to both GitHub Packages and Maven Central.

2. **Monitor the release (optional)**  
   - Go to [https://central.sonatype.com](https://central.sonatype.com)
   - Check `Publish → Deployments`
   - Status typically changes from **Validating → Publishing → Published** within ~40 minutes.
   - _No manual intervention is needed._

3. **Verify availability**:

   ```bash
   mvn dependency:get -Dartifact=io.spicelabs:ginger-j:0.1.0
   ```

4. **Artifacts published**:
   - GitHub Release: [v0.1.0](https://github.com/spice-labs-inc/ginger-j/releases/tag/v0.1.0)
   - GitHub Packages: [ginger-j package](https://github.com/spice-labs-inc/ginger-j/packages)
   - Maven Central: [ginger-j @ central.sonatype.com](https://central.sonatype.com/artifact/io.spicelabs/ginger-j)

---

## 📜 License

Apache-2.0  
© 2025 Spice Labs, Inc. & Contributors