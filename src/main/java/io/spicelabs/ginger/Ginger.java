// SPDX-License-Identifier: Apache-2.0
/* Copyright 2025 Spice Labs, Inc. & Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

package io.spicelabs.ginger;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Single entrypoint for both CLI and Java callers.
 * Picocli binds the annotated fields when run from main(),
 * while Java code can call the builder() methods and then run().
 */
@Command(
    name = "ginger",
    mixinStandardHelpOptions = true,
    version = "1.0",
    description = "Encrypts and uploads either ADGs or deployment events."
)
public class Ginger implements Callable<Integer> {
  private static final Logger log = LoggerFactory.getLogger(Ginger.class);

  //── JWT claim keys ──────────────────────────────────────────────────────────────
  private static final String CLAIM_PUBLIC_KEY = "x-public-key";
  private static final String CLAIM_SERVER     = "x-upload-server";
  private static final String CLAIM_UUID       = "x-uuid-project";
  private static final String CLAIM_EXP        = "exp";
  private static final String CLAIM_CHALLENGE  = "x-challenge";

  //── Full mime types ─────────────────────────────────────────────────────────────
  private static final String MIME_DEPLOY  = "application/vnd.info.deployevent";
  private static final String MIME_BIGTENT = "application/vnd.cc.bigtent";

  //── Error messages ──────────────────────────────────────────────────────────────
  private static final String ERR_INVALID_JWT = "Invalid JWT or file path: ";
  private static final String ERR_NO_JWT      = "JWT not provided; use -j/--jwt";
  private static final String ERR_NO_PUBKEY   = "x-public-key claim missing in JWT";
  private static final String ERR_NO_SERVER   = "x-upload-server claim missing in JWT";
  private static final String ERR_NO_UUID     = "x-uuid-project claim missing in JWT and no --uuid provided";
  private static final String ERR_EXP_INVALID = "exp claim missing or invalid";

  //── Picocli-bound options ──────────────────────────────────────────────────────

  @Option(names = {"-j", "--jwt"}, description = "JWT string or file path" /* , required = true*/)
  private String jwt;

  @Option(names = {"--uuid"}, description = "Override project UUID (else from JWT)")
  private String uuid;

  @Option(names = "--adg", description = "Directory of ADG files to scan & upload")
  private Path adgDir;

  @Option(names = "--deployment-events", description = "JSON file containing deployment events")
  private Path deploymentEventsFile;

  @Option(names = {"-e", "--encrypt-only"}, description = "Only encrypt; do not upload")
  private boolean encryptOnly;

  @Option(names = {"--comment-no-sensitive-info"}, description = "Non-sensitive comment")
  private String comment;

  @Option(names = "--output", description = "Directory to write encrypted zip")
  private Path outputDir;

  @Option(names = "--skip-key", description = "Skip encrypting with a key. Makes a clear-text bundle. Use in combination with '-e' to build a local, clear-text bundle.")
  private boolean skipKey = false;

  @Option(names = "--bundle-format-version", description = "Bundle format version (1 or 2). Default is 1.")
  private int bundleFormatVersion = 2;

  @Option(
      names = "--extra-args",
      description = "Additional Ginger builder args in key=value format (e.g. --extra-args=\"--skip-key,--encrypt-only\")",
      split = ","
  )
  List<String> extraArgsRaw;

  Map<String, String> extraArgs;


  //── Java-first fluent API ──────────────────────────────────────────────────────

  public static Ginger builder() { return new Ginger(); }
  public Ginger jwt(String jwt) { this.jwt = jwt; return this; }
  public Ginger uuid(String uuid) { this.uuid = uuid; return this; }
  public Ginger adgDir(Path adgDir) { this.adgDir = adgDir; return this; }
  public Ginger deploymentEventsFile(Path f) { this.deploymentEventsFile = f; return this; }
  public Ginger encryptOnly(boolean e) { this.encryptOnly = e; return this; }
  public Ginger skipKey(boolean s) {this.skipKey = s; return this;}
  public Ginger comment(String c) { this.comment = c; return this; }
  public Ginger outputDir(Path d) { this.outputDir = d; return this; }
  public Ginger bundleFormatVersion(int v) { this.bundleFormatVersion = v; return this; }
  public Ginger extraArgs(Map<String, String> args) { this.extraArgs = args; return this; }

  /**
   * Perform the work—encrypt (and optionally upload).
   */
  public void run() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    processExtraArgs();
    boolean hasAdg    = adgDir != null;
    boolean hasEvents = deploymentEventsFile != null;
    if (hasAdg == hasEvents) {
      throw new IllegalArgumentException("Must specify exactly one of --adg or --deployment-events");
    }

    Path payload  = hasAdg ? adgDir : deploymentEventsFile;
    String mime   = hasAdg ? MIME_BIGTENT : MIME_DEPLOY;


    // JWT
    String token = null;
    if (!this.skipKey) {
      token = resolveJwt();
    if (!encryptOnly && !isJwtNotExpired()) {
      throw new IllegalArgumentException(ERR_EXP_INVALID);
    }}

    // Public key & server from JWT claims
    Optional<String> pubKey = resolvePublicKeyPem();
    String server = encryptOnly ? null : resolveServerUrl();
    Optional<String> projId = resolveUuid();

    // Stream or tar payload
    BundleFormatVersion version = BundleFormatVersion.fromInt(bundleFormatVersion);
    var stream = PayloadStreamer.stream(payload, version);
    Path outDir = (outputDir != null)
        ? outputDir
        : payload.getParent();

    if (outDir == null || !Files.isWritable(outDir)) {
      outDir = Files.createTempDirectory("ginger-out");
      log.warn("Output dir fallback: using {}", outDir);
    }

    File bundle = ZipBuilder.build(
        projId, pubKey, stream, Files.isDirectory(payload),
        mime, comment, outDir, version
    );

    log.warn("Important! SHA256 hash of bundle is {}", HashUtil.sha256Hex(bundle));

    if (encryptOnly) {
      log.info("Wrote encrypted file to {}", bundle);
      return;
    }

    // Use direct upload flow - challenge is optional (null for old JWTs)
    String challenge = resolveChallenge();
    if (challenge != null) {
      log.info("Using direct upload with encryption challenge verification");
    } else {
      log.info("Using direct upload without challenge (old JWT)");
    }
    DirectUploadService.uploadDirect(
        server,
        token,
        pubKey.orElse(null),
        bundle,
        bundle.getName(),
        challenge
    );
  }

  //── Picocli entrypoint ─────────────────────────────────────────────────────────

  @Override
  public Integer call() throws Exception {
    try {
      Security.addProvider(new BouncyCastleProvider());
      run();
      return 0;
    } catch (Throwable ex) {
      log.error("Error: {}", ex.getMessage());
      if (log.isDebugEnabled()) {
        log.error("Stack trace:", ex);
      }
      return 1;
    }
  }

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());
    int exitCode = new CommandLine(new Ginger())
        .setExecutionStrategy(new CommandLine.RunLast())
        .execute(args);
    System.exit(exitCode);
  }

  //── Configuration resolution helpers ────────────────────────────────────────────

  private JsonNode cachedPayloadNode = null;
  private String cachedJwt = null;

  private String resolveJwt() throws Exception {
    if (cachedJwt != null) return cachedJwt;
    if (jwt == null) throw new IllegalArgumentException(ERR_NO_JWT);
    Path p = Paths.get(jwt);
    if (Files.exists(p) && Files.isRegularFile(p)) {
      cachedJwt = Files.readString(p, StandardCharsets.UTF_8).trim();
    } else {
      try {
        JwtUtil.decodePayload(jwt);
        cachedJwt = jwt;
      } catch (Exception ex) {
        throw new IllegalArgumentException(ERR_INVALID_JWT + jwt);
      }
    }
    return cachedJwt;
  }

  private Optional<String> resolvePublicKeyPem() throws Exception {
    if (this.skipKey) return Optional.empty();
    if (cachedPayloadNode == null) {
      cachedPayloadNode = JwtUtil.decodePayload(resolveJwt());
    }
    String claim = JwtUtil.getStringClaim(cachedPayloadNode, CLAIM_PUBLIC_KEY);
    if (claim != null) return Optional.of(claim);
    throw new IllegalArgumentException(ERR_NO_PUBKEY);
  }

  private String resolveServerUrl() throws Exception {
    if (cachedPayloadNode == null) {
      cachedPayloadNode = JwtUtil.decodePayload(resolveJwt());
    }
    String claim = JwtUtil.getStringClaim(cachedPayloadNode, CLAIM_SERVER);
    if (claim != null) return claim;
    throw new IllegalArgumentException(ERR_NO_SERVER);
  }

  private Optional<String> resolveUuid() throws Exception {
    if (this.skipKey) return Optional.empty();

    JsonNode payloadNode = JwtUtil.decodePayload(resolveJwt());
    String claim = JwtUtil.getStringClaim(payloadNode, CLAIM_UUID);
    if (claim != null) return Optional.of(claim);
    if (uuid != null) return Optional.of(uuid);
    throw new IllegalArgumentException(ERR_NO_UUID);
  }

  private boolean isJwtNotExpired() throws Exception {
    JsonNode payloadNode = JwtUtil.decodePayload(resolveJwt());
    long exp = JwtUtil.getLongClaim(payloadNode, CLAIM_EXP);
    if (exp <= 0) throw new IllegalArgumentException(ERR_EXP_INVALID);
    return Instant.now().getEpochSecond() < exp;
  }

  private String resolveChallenge() throws Exception {
    if (cachedPayloadNode == null) {
      cachedPayloadNode = JwtUtil.decodePayload(resolveJwt());
    }
    return JwtUtil.getStringClaim(cachedPayloadNode, CLAIM_CHALLENGE);
  }

  private void processExtraArgs() {
    if ((extraArgsRaw == null || extraArgsRaw.isEmpty()) && (extraArgs == null || extraArgs.isEmpty())) {
      return;
    }

    List<String> tokens = new ArrayList<>();
    if (extraArgsRaw != null && !extraArgsRaw.isEmpty()) {
      tokens.addAll(extraArgsRaw);
    } else {
      for (Map.Entry<String, String> e : extraArgs.entrySet()) {
        String k = e.getKey();
        String v = e.getValue();
        if (v == null || v.isEmpty()) {
          tokens.add(k);
        } else {
          tokens.add(k + "=" + v);
        }
      }
    }

    for (int i = 0; i < tokens.size(); i++) {
      String raw = tokens.get(i);
      String arg = raw == null ? "" : raw.trim();
       if (arg.isEmpty()) continue;
       String key;
       String value = null;
       int eq = arg.indexOf('=');
       if (eq >= 0) {
         key = arg.substring(0, eq);
         value = arg.substring(eq + 1);
       } else {
         key = arg;
         // If this option expects a value and next token is a non-option, take it as the value.
         if (expectsValue(key) && (i + 1) < tokens.size()) {
           String next = tokens.get(i + 1);
           if (next != null) {
             String nt = next.trim();
             if (!nt.isEmpty() && !nt.startsWith("-")) {
               value = nt;
               i++; // consume next token
             }
           }
         }
         // For comment-no-sensitive-info, allow flag form (no value) mapping to empty string
         if ("--comment-no-sensitive-info".equals(key) && value == null) {
           value = "";
         }
       }

       switch (key) {
         case "--skip-key" -> this.skipKey = true;
         case "--encrypt-only", "-e" -> this.encryptOnly = true;

         case "--jwt", "-j" -> {
           if (value == null || value.isEmpty()) {
             throw new IllegalArgumentException("--jwt requires a value (use --jwt=/path/to/jwt or -j /path)");
           }
           this.jwt = value;
         }

         case "--uuid" -> {
           if (value == null || value.isEmpty()) {
             throw new IllegalArgumentException("--uuid requires a value");
           }
           this.uuid = value;
         }

         case "--adg" -> {
           if (value == null || value.isEmpty()) {
             throw new IllegalArgumentException("--adg requires a value (directory path)");
           }
           this.adgDir = Paths.get(value);
         }

         case "--deployment-events" -> {
           if (value == null || value.isEmpty()) {
             throw new IllegalArgumentException("--deployment-events requires a value (file path)");
           }
           this.deploymentEventsFile = Paths.get(value);
         }

         case "--output" -> {
           if (value == null || value.isEmpty()) {
             throw new IllegalArgumentException("--output requires a value (directory path)");
           }
           this.outputDir = Paths.get(value);
         }

         case "--comment-no-sensitive-info" -> {
           // can be passed as flag or with a value
           this.comment = value;
         }

         case "--comment" -> {
           if (value == null) {
             throw new IllegalArgumentException("--comment requires a value");
           }
           this.comment = value;
         }

         case "--bundle-format-version" -> {
           if (value == null || value.isEmpty()) {
             throw new IllegalArgumentException("--bundle-format-version requires a value (1 or 2)");
           }
           this.bundleFormatVersion = Integer.parseInt(value);
         }

         default -> log.warn("Unknown extra arg: {}", arg);
       }
     }
   }

  private boolean expectsValue(String key) {
    return switch (key) {
      case "--jwt", "-j", "--uuid", "--adg", "--deployment-events",
           "--output", "--comment", "--comment-no-sensitive-info",
           "--bundle-format-version" -> true;
      default -> false;
    };
  }
}
