package io.spicelabs.ginger;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PayloadStreamerTest {
  @Test
  void fileStream(@TempDir Path tempDir) throws Exception {
    Path f = tempDir.resolve("a.txt");
    Files.writeString(f, "hello");
    try (InputStream in = PayloadStreamer.stream(f)) {
      assertEquals("hello", new String(in.readAllBytes()));
    }
  }

  @Test
  void dirStream(@TempDir Path tempDir) throws Exception {
    Path d = tempDir.resolve("d");
    Files.createDirectories(d);
    Files.writeString(d.resolve("x.txt"), "x");
    try (InputStream in = PayloadStreamer.stream(d);
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

    try (InputStream in = PayloadStreamer.stream(d);
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


}