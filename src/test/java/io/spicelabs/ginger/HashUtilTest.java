package io.spicelabs.ginger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class HashUtilTest {
  @Test
  void sha256(@TempDir Path dir) throws Exception {
    Path f = dir.resolve("f.txt");
    Files.writeString(f, "hello");
    String hex = HashUtil.sha256Hex(f.toFile());
    assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hex);
  }
}
