package io.spicelabs.ginger;

import org.junit.jupiter.api.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipFile;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

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
  void bothInputs_adgAndEvents_throws() {
    assertThrows(Exception.class, () -> Ginger.builder()
        .jwt(jwt)
        .adgDir(adgDir)
        .deploymentEventsFile(eventsFile)
        .run(), "Must throw if both inputs are set");
  }

  @Test
  void bothInputs_adgAndRuntimeSurvey_throws() {
    assertThrows(Exception.class, () -> Ginger.builder()
        .jwt(jwt)
        .adgDir(adgDir)
        .runtimeSurveyFile(eventsFile)
        .run(), "Must throw if both inputs are set");
  }

  @Test
  void allThreeInputs_throws() {
    assertThrows(Exception.class, () -> Ginger.builder()
        .jwt(jwt)
        .adgDir(adgDir)
        .deploymentEventsFile(eventsFile)
        .runtimeSurveyFile(eventsFile)
        .run(), "Must throw if all three inputs are set");
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

  @Test
  void encryptOnly_runtimeSurvey_succeeds_andCreatesZip() throws Exception {
    Path surveyFile = tmp.resolve("survey.json");
    Files.writeString(surveyFile, "{\"type\":\"runtime-pqc-survey\",\"subject\":\"test\"}",
        StandardCharsets.UTF_8);

    Ginger.builder()
        .jwt(jwt)
        .runtimeSurveyFile(surveyFile)
        .encryptOnly(true)
        .run();

    try (Stream<Path> files = Files.walk(tmp)) {
      long zips = files.filter(p -> p.toString().endsWith(".zip")).count();
      assertEquals(1, zips);
    }
  }

  @Test
  void afterBundleWrapped_firesOnceAfterWrapInEncryptOnly() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    Ginger.builder()
        .jwt(jwt)
        .adgDir(adgDir)
        .encryptOnly(true)
        .afterBundleWrapped(calls::incrementAndGet)
        .run();
    assertEquals(1, calls.get(), "callback should fire exactly once after wrap");
  }

  @Test
  void afterBundleWrapped_swallowsCallbackException() {
    AtomicBoolean fired = new AtomicBoolean(false);
    assertDoesNotThrow(() ->
        Ginger.builder()
            .jwt(jwt)
            .adgDir(adgDir)
            .encryptOnly(true)
            .afterBundleWrapped(() -> {
              fired.set(true);
              throw new RuntimeException("listener went sideways");
            })
            .run());
    assertTrue(fired.get(), "callback must run before its exception is swallowed");
  }

  @Test
  void publishStatus_isNoOpWhenParentIdMissing() {
    // No throw, no network call — exits on the parentId null check.
    assertDoesNotThrow(() ->
        Ginger.builder()
            .jwt(jwt)
            .publishStatus(UUID.randomUUID(), "RUNNING", 10, "hello"));
  }

  @Test
  void publishStatus_isNoOpWhenSubJobIdMissing() {
    assertDoesNotThrow(() ->
        Ginger.builder()
            .jwt(jwt)
            .parentId(UUID.randomUUID())
            .publishStatus(null, "RUNNING", 10, "hello"));
  }

  @Test
  void publishStatus_swallowsMissingJwt() {
    // No JWT configured — resolveJwt would throw; publishStatus catches it silently.
    assertDoesNotThrow(() ->
        Ginger.builder()
            .parentId(UUID.randomUUID())
            .publishStatus(UUID.randomUUID(), "RUNNING", 10, "hello"));
  }

  @Test
  void runtimeSurveyOnly_noOtherInputs_accepted() throws Exception {
    Path surveyFile = tmp.resolve("survey.json");
    Files.writeString(surveyFile, "{\"type\":\"runtime-pqc-survey\"}",
        StandardCharsets.UTF_8);

    // Should not throw during validation (will fail at upload since server is fake)
    Ginger g = Ginger.builder()
        .jwt(jwt)
        .runtimeSurveyFile(surveyFile)
        .encryptOnly(true);
    assertDoesNotThrow(g::run);
  }

  @Test
  void bothInputs_runtimeAndStaticSurvey_throws() throws IOException {
    Path surveyFile = writeStaticSurvey();
    assertThrows(Exception.class, () -> Ginger.builder()
        .jwt(jwt)
        .runtimeSurveyFile(surveyFile)
        .staticSurveyFile(surveyFile)
        .encryptOnly(true)
        .run(), "Must throw if both inputs are set");
  }

  @Test
  void staticSurveyOnly_noOtherInputs_accepted() throws Exception {
    Ginger g = Ginger.builder()
        .jwt(jwt)
        .staticSurveyFile(writeStaticSurvey())
        .encryptOnly(true);
    assertDoesNotThrow(g::run);
  }

  @Test
  void encryptOnly_staticSurvey_createsZipWithStaticSurveyMime() throws Exception {
    Ginger.builder()
        .jwt(jwt)
        .staticSurveyFile(writeStaticSurvey())
        .subject("app.jar")
        .encryptOnly(true)
        .run();

    Path zip;
    try (Stream<Path> files = Files.walk(tmp)) {
      zip = files.filter(p -> p.toString().endsWith(".zip")).findFirst().orElseThrow();
    }
    try (ZipFile zf = new ZipFile(zip.toFile())) {
      String mime = new String(zf.getInputStream(zf.getEntry("mime.txt")).readAllBytes(),
          StandardCharsets.UTF_8);
      assertEquals("application/x-vnd.spicelabs.static-survey", mime);
    }
  }

  private Path writeStaticSurvey() throws IOException {
    Path surveyFile = tmp.resolve("lintium.json");
    Files.writeString(surveyFile,
        "{\"gitoid_sha256\":\"gitoid:blob:sha256:00\",\"artifact\":{\"path\":\"app.jar\"},\"findings\":[]}",
        StandardCharsets.UTF_8);
    return surveyFile;
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


  @Test
  void downloadRuntimeConfig_sendsTheUserAgent() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse().setResponseCode(200).setBody("{}"));
      server.start();
      String body = "{\"exp\":" + (Instant.now().getEpochSecond() + 3600)
          + ",\"x-upload-server\":\"" + server.url("/api/v1/project/p/bundle/upload") + "\"}";
      String jwt = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8))
          + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(body.getBytes(StandardCharsets.UTF_8)) + ".";

      byte[] config = Ginger.builder().jwt(jwt).userAgent("spice-labs-cli/1.2.3 (command survey runtime)")
          .downloadRuntimeConfigBytes();

      assertArrayEquals("{}".getBytes(StandardCharsets.UTF_8), config);
      RecordedRequest req = server.takeRequest(1, TimeUnit.SECONDS);
      assertEquals("/api/v1/project/p/bundle/upload/runtime-config", req.getPath());
      assertEquals("spice-labs-cli/1.2.3 (command survey runtime)", req.getHeader("User-Agent"));
    }
  }
}
