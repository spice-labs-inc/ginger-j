package io.spicelabs.ginger;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.*;

class PayloadStreamerTest {
  @Test
  void fileStream(@TempDir Path tempDir) throws Exception {
    Path f = tempDir.resolve("a.txt");
    Files.writeString(f, "hello");
    try (InputStream in = PayloadStreamer.stream(f, BundleFormatVersion.VERSION_1)) {
      assertEquals("hello", new String(in.readAllBytes()));
    }
  }

  @Test
  void dirStream(@TempDir Path tempDir) throws Exception {
    Path d = tempDir.resolve("d");
    Files.createDirectories(d);
    Files.writeString(d.resolve("x.txt"), "x");
    try (InputStream in = PayloadStreamer.stream(d, BundleFormatVersion.VERSION_1);
         TarArchiveInputStream tais = new TarArchiveInputStream(in)) {
      boolean saw = false;
      TarArchiveEntry e;

      while ((e = tais.getNextEntry()) != null) {
        if (e.getName().equals("x.txt")) saw = true;
      }
      assertTrue(saw);
    }
  }

  @Test
  void dirStream_withLongFilename_doesNotThrow(@TempDir Path tempDir) throws Exception {
    Path d = tempDir.resolve("longpath");
    Files.createDirectories(d);

    // filename > 100 bytes
    String longFileName = "a".repeat(101);
    Path longFile = d.resolve(longFileName);
    Files.writeString(longFile, "oops");

    try (InputStream in = PayloadStreamer.stream(d, BundleFormatVersion.VERSION_1);
         TarArchiveInputStream tais = new TarArchiveInputStream(in)) {

      boolean found = false;
      TarArchiveEntry entry;
      while ((entry = tais.getNextEntry()) != null) {
        if (entry.getName().equals(longFileName)) {
          found = true;
          break;
        }
      }
      assertTrue(found, "Expected long filename entry in tar stream");
    } catch (Exception e) {
      fail("Expected no exception, but got: " + e);
    }
  }

  @Test
  void dirStream_version2_actuallyCompresses(@TempDir Path tempDir) throws Exception {
    Path d = tempDir.resolve("d");
    Files.createDirectories(d);
    Files.writeString(d.resolve("large.txt"), "x".repeat(10000));

    byte[] v1Data, v2Data;

    try (InputStream in = PayloadStreamer.stream(d, BundleFormatVersion.VERSION_1)) {
      v1Data = in.readAllBytes();
    }

    try (InputStream in = PayloadStreamer.stream(d, BundleFormatVersion.VERSION_2)) {
      v2Data = in.readAllBytes();
    }

    assertTrue(v2Data.length < v1Data.length,
        "V2 should be smaller: V1=" + v1Data.length + " V2=" + v2Data.length);

    File zipV1 = ZipBuilder.build(Optional.empty(), Optional.empty(),
        PayloadStreamer.stream(d, BundleFormatVersion.VERSION_1), true,
        "test/mime", null, tempDir, BundleFormatVersion.VERSION_1);
    File zipV2 = ZipBuilder.build(Optional.empty(), Optional.empty(),
        PayloadStreamer.stream(d, BundleFormatVersion.VERSION_2), true,
        "test/mime", null, tempDir, BundleFormatVersion.VERSION_2);

    try (ZipFile zfV1 = new ZipFile(zipV1);
         ZipFile zfV2 = new ZipFile(zipV2)) {
      assertEquals("tar", new String(zfV1.getInputStream(zfV1.getEntry("payload_container_type.txt")).readAllBytes()));
      assertEquals("tar.gz", new String(zfV2.getInputStream(zfV2.getEntry("payload_container_type.txt")).readAllBytes()));
    }
  }

}