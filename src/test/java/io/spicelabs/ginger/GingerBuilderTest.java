package io.spicelabs.ginger;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class GingerBuilderTest {
  private Path tmp;
  private Path adgDir;
  private Path eventsFile;
  private String jwt;

  @BeforeEach
  void setUp() throws IOException {
    tmp = Files.createTempDirectory("ginger-test-");

    adgDir = tmp.resolve("adg");
    Files.createDirectories(adgDir);
    Files.writeString(adgDir.resolve("one.grc"), "");
    Files.writeString(adgDir.resolve("two.grd"), "");
    Files.writeString(adgDir.resolve("three.gri"), "");

    eventsFile = tmp.resolve("events.json");
    String json = "[{\"identifier\":\"ID\",\"system\":\"SYS\",\"artifact\":\"ART\",\"start_time\":\""
        + Instant.now().toString() + "\"}]";
    Files.writeString(eventsFile, json, StandardCharsets.UTF_8);

    jwt = makeDummyJwt();
  }

  @AfterEach
  void tearDown() throws IOException {
    try (Stream<Path> walk = Files.walk(tmp)) {
      walk.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
    }
  }

  @Test
  void noInputsOrJwt_throws() {
    assertThrows(Exception.class, () -> Ginger.builder().run(), "Must throw with neither JWT nor input");
  }

  @Test
  void missingJwt_throws() {
    assertThrows(Exception.class, () -> Ginger.builder().adgDir(adgDir).run(), "Must throw without JWT");
  }

  @Test
  void missingInput_throws() {
    assertThrows(Exception.class, () -> Ginger.builder().jwt(jwt).run(), "Must throw without input");
  }

  @Test
  void bothInputs_throws() {
    assertThrows(Exception.class, () -> Ginger.builder()
        .jwt(jwt)
        .adgDir(adgDir)
        .deploymentEventsFile(eventsFile)
        .run(), "Must throw if both inputs are set");
  }

  @Test
  void encryptOnly_adg_succeeds_andCreatesZip() throws Exception {
    Ginger.builder()
        .jwt(jwt)
        .adgDir(adgDir)
        .encryptOnly(true)
        .run();

    try (Stream<Path> files = Files.walk(tmp)) {
      long zips = files.filter(p -> p.toString().endsWith(".zip")).count();
      assertEquals(1, zips);
    }
  }

  @Test
  void encryptOnly_events_succeeds_andCreatesZip() throws Exception {
    Ginger.builder()
        .jwt(jwt)
        .deploymentEventsFile(eventsFile)
        .encryptOnly(true)
        .run();

    try (Stream<Path> files = Files.walk(tmp)) {
      long zips = files.filter(p -> p.toString().endsWith(".zip")).count();
      assertEquals(1, zips);
    }
  }

  public static String makeDummyJwt() {
    String header = Base64.getUrlEncoder().withoutPadding()
        .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));

    long exp = Instant.now().plusSeconds(3600).getEpochSecond();

    String pubKey = """
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueXpAvrZRxurDHMGEO7l
      d4SmgnarL/fZW1vWgqZeq7/jY1ZevvNclga9+OjhwAKcFE4AJd2JPuhB0fUSpCOE
      gkCTFGTC5MLpR/5DUHc8gJfBbtTF8DzjV/FiqUTg9Cybrw/hm3ANXGUKMiVgTACn
      7NVLz5tZxT0kI43vWIMmN0Yz6+w38eOHM5kT8syG54C9GoYcmMiBLsEzTzvmc1el
      kcrJHeHguFiKMbAMsSzMJvjGzOb3T8idvwi+Hc25TevZHKHKwhl2EIm2fSM+I38l
      zqRaAIcGk39qQHbUt+7w14X59LK4axTeAS7hI7OtH29zEuDDVYhzx7Bml0PV2L9N
      4QIDAQAB
      -----END PUBLIC KEY-----
      """;

    String bodyJson = String.format(
        "{\"exp\":%d,\"x-uuid-project\":\"my-uuid\"," +
            "\"x-public-key\":%s," +
            "\"x-upload-server\":\"https://example.com/upload\"}",
        exp,
        quoteJson(pubKey)
    );

    String payload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));

    return header + "." + payload + ".";
  }

  private static String quoteJson(String s) {
    return "\"" + s.replace("\n", "\\n").replace("\"", "\\\"") + "\"";
  }


}