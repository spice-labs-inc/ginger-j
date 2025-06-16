package io.spicelabs.ginger;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class HttpUploaderTest {
  @Test
  void uploadSuccess(@TempDir Path dir) throws Exception {

    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse().setResponseCode(200));
      server.start();

      Path f = dir.resolve("b.zip");
      Files.writeString(f, "x");
      String url = server.url("/").toString();
      assertDoesNotThrow(() -> HttpUploader.upload(url, "tok", f.toFile()));
    }
  }

  @Test
  void uploadFailure(@TempDir Path dir) throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse().setResponseCode(500).setBody("err"));
      server.start();

      Path f = dir.resolve("b.zip");
      Files.writeString(f, "x");
      String url = server.url("/").toString();
      IOException ex = assertThrows(IOException.class,
          () -> HttpUploader.upload(url, "tok", f.toFile()));
      assertTrue(ex.getMessage().contains("Upload failed"));
    }
  }
}
