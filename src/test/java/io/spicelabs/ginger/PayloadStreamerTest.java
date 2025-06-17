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
}