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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZipBuilder {
  private static final String ENTRY_UUID = "uuid.txt";
  private static final String ENTRY_DATE = "bundle_date.txt";
  private static final String ENTRY_CONTAINER = "payload_container_type.txt";
  private static final String ENTRY_COMMENT = "comment.txt";
  private static final String ENTRY_VERSION = "bundle_format_version.txt";
  private static final String ENTRY_KEY = "key.txt";
  private static final String ENTRY_PUBKEY = "pubkey.pem";
  private static final String ENTRY_IV = "iv.txt";
  private static final String ENTRY_MIME = "mime.txt";
  private static final String ENTRY_PAYLOAD = "payload.enc";
  private static final String ENTRY_TEST = "test.txt";

  private static final String TYPE_TAR = "tar";
  private static final String TYPE_FILE = "file";

  private static final byte[] BUNDLE_VERSION = "1".getBytes();
  private static final String ZIP_EXTENSION = ".zip";
  private static final String PROP_TMPDIR = "java.io.tmpdir";

  public static File build(String uuid,
                           String pubKeyPem,
                           InputStream payloadStream,
                           boolean payloadIsTar,
                           String mimeType,
                           String comment,
                           Path outputDir) throws Exception {

    Path dir = (outputDir != null)
        ? outputDir
        : Paths.get(System.getProperty(PROP_TMPDIR));

    String fileName = String.format("%s-%d%s",
        uuid,
        Instant.now().toEpochMilli(),
        ZIP_EXTENSION
    );
    Path zip = dir.resolve(fileName);

    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zip))) {
      writeEntry(zos, ENTRY_UUID, uuid.getBytes());
      writeEntry(zos, ENTRY_DATE, Instant.now().toString().getBytes());

      String containerType = payloadIsTar ? TYPE_TAR : TYPE_FILE;
      writeEntry(zos, ENTRY_CONTAINER, containerType.getBytes());

      if (comment != null) {
        writeEntry(zos, ENTRY_COMMENT, comment.getBytes());
      }

      writeEntry(zos, ENTRY_VERSION, BUNDLE_VERSION);

      byte[] aesKey = CryptoUtil.generateAesKey();
      byte[] encKey = CryptoUtil.encryptWithRsa(pubKeyPem, aesKey);
      writeEntry(zos, ENTRY_KEY, Base64.getEncoder().encode(encKey));

      writeEntry(zos, ENTRY_PUBKEY, pubKeyPem.getBytes());

      // === test.txt logic ===
      byte[] testIv = CryptoUtil.generateIv();
      byte[] testPlain = CryptoUtil.randomBytes(128);
      ByteArrayOutputStream encryptedTest = new ByteArrayOutputStream();

      if (payloadStream == null) throw new IllegalArgumentException("Payload stream is null");

      CryptoUtil.aesGcmEncrypt(aesKey, testIv, new ByteArrayInputStream(testPlain), encryptedTest);

      String testEntry = String.join(
          "\n",
          Base64.getEncoder().encodeToString(testIv),
          Base64.getEncoder().encodeToString(testPlain),
          Base64.getEncoder().encodeToString(encryptedTest.toByteArray())
      );
      writeEntry(zos, ENTRY_TEST, testEntry.getBytes(StandardCharsets.UTF_8));
      // === end test.txt logic ===

      byte[] iv = CryptoUtil.generateIv();
      writeEntry(zos, ENTRY_IV, Base64.getEncoder().encode(iv));
      writeEntry(zos, ENTRY_MIME, mimeType.getBytes());

      zos.putNextEntry(new ZipEntry(ENTRY_PAYLOAD));
      CryptoUtil.aesGcmEncrypt(aesKey, iv, payloadStream, zos);
      zos.closeEntry();
    }

    return zip.toFile();
  }

  private static void writeEntry(ZipOutputStream zos, String name, byte[] data)
      throws IOException {
    zos.putNextEntry(new ZipEntry(name));
    zos.write(data);
    zos.closeEntry();
  }
}