package io.spicelabs.ginger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ValidatorsTest {
  @Test
  void validDeploy(@TempDir Path dir) throws Exception {
    Files.writeString(dir.resolve("e.json"),
        "{\"identifier\":\"i\",\"system\":\"s\",\"artifact\":\"a\",\"start_time\":\"t\"}");
    assertDoesNotThrow(() -> Validators.validateDeployEvents(dir));
  }

  @Test
  void invalidDeploy(@TempDir Path dir) {
    Exception ex = assertThrows(Exception.class,
        () -> Validators.validateDeployEvents(dir));
    assertTrue(ex.getMessage().contains("No valid"));
  }

  @Test
  void validCluster(@TempDir Path dir) throws Exception {
    Files.writeString(dir.resolve("x.grc"), "");
    Files.writeString(dir.resolve("y.grd"), "");
    Files.writeString(dir.resolve("z.gri"), "");
    assertDoesNotThrow(() -> Validators.validateClusters(dir));
  }
}
