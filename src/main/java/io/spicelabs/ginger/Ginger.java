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

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.concurrent.Callable;

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

  @Option(names = {"-j", "--jwt"}, description = "JWT string or file path", required = true)
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

  //── Java-first fluent API ──────────────────────────────────────────────────────

  public static Ginger builder() { return new Ginger(); }
  public Ginger jwt(String jwt) { this.jwt = jwt; return this; }
  public Ginger uuid(String uuid) { this.uuid = uuid; return this; }
  public Ginger adgDir(Path adgDir) { this.adgDir = adgDir; return this; }
  public Ginger deploymentEventsFile(Path f) { this.deploymentEventsFile = f; return this; }
  public Ginger encryptOnly(boolean e) { this.encryptOnly = e; return this; }
  public Ginger comment(String c) { this.comment = c; return this; }

  /**
   * Perform the work—encrypt (and optionally upload).
   */
  public void run() throws Exception {
    boolean hasAdg    = adgDir != null;
    boolean hasEvents = deploymentEventsFile != null;
    if (hasAdg == hasEvents) {
      throw new IllegalArgumentException("Must specify exactly one of --adg or --deployment-events");
    }

    Path payload  = hasAdg ? adgDir : deploymentEventsFile;
    String mime   = hasAdg ? MIME_BIGTENT : MIME_DEPLOY;

    // JWT
    String token = resolveJwt();
    if (!encryptOnly && !isJwtNotExpired()) {
      throw new IllegalArgumentException(ERR_EXP_INVALID);
    }

    // Public key & server from JWT claims
    String pubKey = resolvePublicKeyPem();
    String server = encryptOnly ? null : resolveServerUrl();
    String projId = resolveUuid();

    // Stream or tar payload
    var stream = PayloadStreamer.stream(payload);
    Path outDir = null;
    if (encryptOnly) {
      Path parent = payload.getParent();
      if (parent != null && Files.isWritable(parent)) {
        outDir = parent;
      } else {
        outDir = Files.createTempDirectory("ginger-out");
        log.warn("Output dir fallback: using {}", outDir);
      }
    }


    File bundle = ZipBuilder.build(
        projId, pubKey, stream, Files.isDirectory(payload),
        mime, comment, outDir
    );

    log.warn("Important! SHA256 hash of bundle is {}", HashUtil.sha256Hex(bundle));

    if (encryptOnly) {
      log.info("Wrote encrypted file to {}", bundle);
      return;
    }

    HttpUploader.upload(server, token, bundle);
    return;
  }

  //── Picocli entrypoint ─────────────────────────────────────────────────────────

  @Override
  public Integer call() throws Exception {
    try {
      run();
      return 0;
    } catch (Exception ex) {
      log.error("Error: {}", ex.getMessage());
      if (log.isDebugEnabled()) {
        log.error("Stack trace:", ex);
      }
      return 1;
    }
  }

  public static void main(String[] args) {
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

  private String resolvePublicKeyPem() throws Exception {
    if (cachedPayloadNode == null) {
      cachedPayloadNode = JwtUtil.decodePayload(resolveJwt());
    }
    String claim = JwtUtil.getStringClaim(cachedPayloadNode, CLAIM_PUBLIC_KEY);
    if (claim != null) return claim;
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

  private String resolveUuid() throws Exception {
    JsonNode payloadNode = JwtUtil.decodePayload(resolveJwt());
    String claim = JwtUtil.getStringClaim(payloadNode, CLAIM_UUID);
    if (claim != null) return claim;
    if (uuid != null) return uuid;
    throw new IllegalArgumentException(ERR_NO_UUID);
  }

  private boolean isJwtNotExpired() throws Exception {
    JsonNode payloadNode = JwtUtil.decodePayload(resolveJwt());
    long exp = JwtUtil.getLongClaim(payloadNode, CLAIM_EXP);
    if (exp <= 0) throw new IllegalArgumentException(ERR_EXP_INVALID);
    return Instant.now().getEpochSecond() < exp;
  }
}
