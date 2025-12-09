package io.spicelabs.ginger;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

class DirectUploadServiceTest {
    private MockWebServer mockServer;
    private MockWebServer storageServer;
    private DirectUploadService service;
    private File testBundle;

    @BeforeEach
    void setUp() throws Exception {
        mockServer = new MockWebServer();
        mockServer.start();

        storageServer = new MockWebServer();
        storageServer.start();

        OkHttpClient testClient = new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .writeTimeout(5, TimeUnit.SECONDS)
                .build();
        service = new DirectUploadService(testClient);

        testBundle = Files.createTempFile("test-bundle-", ".bin").toFile();
        try (FileOutputStream fos = new FileOutputStream(testBundle)) {
            fos.write("test content".getBytes());
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        mockServer.shutdown();
        storageServer.shutdown();
        if (testBundle != null && testBundle.exists()) {
            testBundle.delete();
        }
    }

    private String buildInitResponse(String bundleId, String uploadId, String blobKey, String presignedUrl) {
        return String.format(
                "{\"uploadId\":\"%s\",\"blobKey\":\"%s\",\"bundleId\":\"%s\",\"expiresIn\":3600," +
                "\"parts\":[{\"partNumber\":1,\"presignedUrl\":\"%s\",\"offset\":0,\"size\":12}]}",
                uploadId, blobKey, bundleId, presignedUrl);
    }

    @Test
    void uploadDirect_success() throws Exception {
        String bundleId = "bundle-123";
        String uploadId = "upload-456";
        String blobKey = "external/proj-uuid/bundle-123.12345.blob";
        String presignedUrl = storageServer.url("/upload").toString();

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse(bundleId, uploadId, blobKey, presignedUrl)));

        storageServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("ETag", "\"abc123\""));

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(String.format(
                        "{\"status\":\"completed\",\"bundleId\":\"%s\",\"message\":\"Upload successful\"}",
                        bundleId)));

        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null);

        assertEquals(2, mockServer.getRequestCount());
        assertEquals(1, storageServer.getRequestCount());

        RecordedRequest initRequest = mockServer.takeRequest();
        assertEquals("/api/global/v1/bundle/upload/init", initRequest.getPath());
        assertEquals("Bearer test-jwt", initRequest.getHeader("Authorization"));
        assertTrue(initRequest.getBody().readUtf8().contains("\"sha256\":"));

        RecordedRequest storageRequest = storageServer.takeRequest();
        assertEquals("/upload", storageRequest.getPath());
        assertEquals("PUT", storageRequest.getMethod());

        RecordedRequest completeRequest = mockServer.takeRequest();
        assertEquals("/api/global/v1/bundle/upload/complete", completeRequest.getPath());
        String completeBody = completeRequest.getBody().readUtf8();
        assertTrue(completeBody.contains("\"uploadId\":\"upload-456\""));
        assertTrue(completeBody.contains("\"blobKey\":\"external/proj-uuid/bundle-123.12345.blob\""));
        assertTrue(completeBody.contains("\"parts\":[{\"partNumber\":1,\"etag\":\"abc123\"}]"));
    }

    @Test
    void uploadDirect_initFailure_throws() {
        mockServer.enqueue(new MockResponse()
                .setResponseCode(401)
                .setBody("{\"error\":\"Unauthorized\"}"));

        IOException ex = assertThrows(IOException.class, () ->
                service.uploadDirect(
                        mockServer.url("/api/global/v1/bundle/upload").toString(),
                        "bad-jwt",
                        null,
                        testBundle,
                        "test.bin",
                        null));

        assertTrue(ex.getMessage().contains("401"));
    }

    @Test
    void uploadDirect_storageFailure_throws() {
        String presignedUrl = storageServer.url("/upload").toString();

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("bid", "uid", "bkey", presignedUrl)));

        storageServer.enqueue(new MockResponse().setResponseCode(500).setBody("Internal error"));
        storageServer.enqueue(new MockResponse().setResponseCode(500).setBody("Internal error"));
        storageServer.enqueue(new MockResponse().setResponseCode(500).setBody("Internal error"));

        IOException ex = assertThrows(IOException.class, () ->
                service.uploadDirect(
                        mockServer.url("/api/global/v1/bundle/upload").toString(),
                        "test-jwt",
                        null,
                        testBundle,
                        "test.bin",
                        null));

        assertTrue(ex.getMessage().contains("Part upload failed") || ex.getMessage().contains("500"));
    }

    @Test
    void uploadDirect_completeFailure_throws() {
        String presignedUrl = storageServer.url("/upload").toString();

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("bid", "uid", "bkey", presignedUrl)));

        storageServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("ETag", "\"etag1\""));

        mockServer.enqueue(new MockResponse()
                .setResponseCode(400)
                .setBody("{\"error\":\"Invalid request\"}"));

        IOException ex = assertThrows(IOException.class, () ->
                service.uploadDirect(
                        mockServer.url("/api/global/v1/bundle/upload").toString(),
                        "test-jwt",
                        null,
                        testBundle,
                        "test.bin",
                        null));

        assertTrue(ex.getMessage().contains("400"));
    }

    @Test
    void uploadDirect_retryOn5xx_succeeds() throws Exception {
        String presignedUrl = storageServer.url("/upload").toString();

        mockServer.enqueue(new MockResponse().setResponseCode(503).setBody("Service unavailable"));
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("bid", "uid", "bkey", presignedUrl)));

        storageServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("ETag", "\"etag1\""));

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody("{\"status\":\"completed\",\"bundleId\":\"bid\"}"));

        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null);

        assertEquals(3, mockServer.getRequestCount());
    }

    @Test
    void uploadDirect_withChallenge_encryptsChallenge() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()) +
                "\n-----END PUBLIC KEY-----";

        String presignedUrl = storageServer.url("/upload").toString();

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("bid", "uid", "bkey", presignedUrl)));

        storageServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("ETag", "\"etag1\""));

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody("{\"status\":\"completed\",\"bundleId\":\"bid\"}"));

        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                publicKeyPem,
                testBundle,
                "test.bin",
                "test-challenge");

        RecordedRequest initRequest = mockServer.takeRequest();
        String body = initRequest.getBody().readUtf8();
        assertTrue(body.contains("\"encryptedChallenge\":"));
    }

    @Test
    void uploadDirect_challengeWithoutPublicKey_throws() {
        IOException ex = assertThrows(IOException.class, () ->
                service.uploadDirect(
                        mockServer.url("/api/global/v1/bundle/upload").toString(),
                        "test-jwt",
                        null,
                        testBundle,
                        "test.bin",
                        "challenge-without-key"));

        assertTrue(ex.getMessage().contains("Public key is required"));
    }

    @Test
    void uploadDirect_trailingSlashNormalized() throws Exception {
        String presignedUrl = storageServer.url("/upload").toString();

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("bid", "uid", "bkey", presignedUrl)));

        storageServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("ETag", "\"etag1\""));

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody("{\"status\":\"completed\",\"bundleId\":\"bid\"}"));

        String baseUrl = mockServer.url("/api/global/v1/bundle/upload").toString();
        if (!baseUrl.endsWith("/")) {
            baseUrl = baseUrl + "/";
        }

        service.uploadDirect(
                baseUrl,
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null);

        RecordedRequest initRequest = mockServer.takeRequest();
        assertEquals("/api/global/v1/bundle/upload/init", initRequest.getPath());
    }

    @Test
    void uploadDirect_noEtag_throws() {
        String presignedUrl = storageServer.url("/upload").toString();

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("bid", "uid", "bkey", presignedUrl)));

        storageServer.enqueue(new MockResponse().setResponseCode(200));

        IOException ex = assertThrows(IOException.class, () ->
                service.uploadDirect(
                        mockServer.url("/api/global/v1/bundle/upload").toString(),
                        "test-jwt",
                        null,
                        testBundle,
                        "test.bin",
                        null));

        // The exception may be wrapped, check full chain
        Throwable cause = ex;
        boolean foundEtagMessage = false;
        while (cause != null) {
            if (cause.getMessage() != null && cause.getMessage().contains("ETag")) {
                foundEtagMessage = true;
                break;
            }
            cause = cause.getCause();
        }
        assertTrue(foundEtagMessage, "Expected ETag error in exception chain, got: " + ex.getMessage());
    }
}
