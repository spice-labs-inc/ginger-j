package io.spicelabs.ginger;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
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
                "{\"uploadId\":\"%s\",\"blobKey\":\"%s\",\"bundleId\":\"%s\",\"jobId\":\"job-789\",\"expiresIn\":3600," +
                "\"parts\":[{\"partNumber\":1,\"presignedUrl\":\"%s\",\"offset\":0,\"size\":12}]}",
                uploadId, blobKey, bundleId, presignedUrl);
    }

    /**
     * Enqueue the complete-upload response so the test tolerates the racy, fire-and-forget
     * progress request. Progress and complete arrive in any order, so we serve the complete
     * body for both slots — {@code /complete} always gets a valid body regardless of ordering.
     */
    private void enqueueCompleteResponse(String body) {
        mockServer.enqueue(new MockResponse().setResponseCode(200).setBody(body));
        mockServer.enqueue(new MockResponse().setResponseCode(200).setBody(body));
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

        // Progress (fire-and-forget) and complete race; serve the complete body for both slots.
        enqueueCompleteResponse(String.format(
                "{\"status\":\"completed\",\"bundleId\":\"%s\",\"message\":\"Upload successful\"}",
                bundleId));

        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null);

        assertEquals(1, storageServer.getRequestCount());

        RecordedRequest initRequest = mockServer.takeRequest();
        assertEquals("/api/global/v1/bundle/upload/init", initRequest.getPath());
        assertEquals("Bearer test-jwt", initRequest.getHeader("Authorization"));
        assertTrue(initRequest.getBody().readUtf8().contains("\"sha256\":"));

        RecordedRequest storageRequest = storageServer.takeRequest();
        assertEquals("/upload", storageRequest.getPath());
        assertEquals("PUT", storageRequest.getMethod());

        // Drain remaining requests to find the complete request
        RecordedRequest req;
        String completeBody = null;
        while ((req = mockServer.takeRequest(1, TimeUnit.SECONDS)) != null) {
            if (req.getPath().equals("/api/global/v1/bundle/upload/complete")) {
                completeBody = req.getBody().readUtf8();
            }
        }
        assertNotNull(completeBody, "Should have received complete request");
        assertTrue(completeBody.contains("\"uploadId\":\"upload-456\""));
        assertTrue(completeBody.contains("\"blobKey\":\"external/proj-uuid/bundle-123.12345.blob\""));
        assertTrue(completeBody.contains("\"jobId\":\"job-789\""));
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

        // Complete and progress report can arrive in any order since progress
        // is fire-and-forget on a virtual thread. Enqueue 400 for both so the
        // complete request always gets 400 regardless of ordering.
        mockServer.enqueue(new MockResponse()
                .setResponseCode(400)
                .setBody("{\"error\":\"Invalid request\"}"));
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

        // Progress (fire-and-forget) and complete race; serve the complete body for both slots.
        enqueueCompleteResponse("{\"status\":\"completed\",\"bundleId\":\"bid\"}");

        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null);
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

        // Progress (fire-and-forget) and complete race; serve the complete body for both slots.
        enqueueCompleteResponse("{\"status\":\"completed\",\"bundleId\":\"bid\"}");

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

        // Progress (fire-and-forget) and complete race; serve the complete body for both slots.
        enqueueCompleteResponse("{\"status\":\"completed\",\"bundleId\":\"bid\"}");

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

    @Test
    void uploadDirect_idempotencyKey_sentOnInitAndComplete() throws Exception {
        String presignedUrl = storageServer.url("/upload").toString();
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("b", "u", "external/p/b.blob", presignedUrl)));
        storageServer.enqueue(new MockResponse().setResponseCode(200).addHeader("ETag", "\"e\""));
        enqueueCompleteResponse("{\"status\":\"completed\",\"bundleId\":\"b\",\"message\":\"ok\"}");

        UUID idemp = UUID.randomUUID();
        DirectUploadService.UploadOptions opts = new DirectUploadService.UploadOptions(
                null, null, null, null, idemp, null);
        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null,
                opts);

        // The init request and the complete request should both carry the Idempotency-Key header.
        boolean initHadHeader = false;
        boolean completeHadHeader = false;
        RecordedRequest req;
        while ((req = mockServer.takeRequest(1, TimeUnit.SECONDS)) != null) {
            if (req.getPath().endsWith("/init")) {
                initHadHeader = idemp.toString().equals(req.getHeader("Idempotency-Key"));
            } else if (req.getPath().endsWith("/complete")) {
                completeHadHeader = idemp.toString().equals(req.getHeader("Idempotency-Key"));
            }
        }
        assertTrue(initHadHeader, "init request should carry Idempotency-Key");
        assertTrue(completeHadHeader, "complete request should carry Idempotency-Key");
    }

    @Test
    void uploadDirect_parentId_sentInInitBody() throws Exception {
        String presignedUrl = storageServer.url("/upload").toString();
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("b", "u", "external/p/b.blob", presignedUrl)));
        storageServer.enqueue(new MockResponse().setResponseCode(200).addHeader("ETag", "\"e\""));
        enqueueCompleteResponse("{\"status\":\"completed\",\"bundleId\":\"b\",\"message\":\"ok\"}");

        UUID parentId = UUID.randomUUID();
        DirectUploadService.UploadOptions opts = new DirectUploadService.UploadOptions(
                null, null, null, parentId, null, null);
        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null,
                opts);

        RecordedRequest initRequest = mockServer.takeRequest();
        assertTrue(initRequest.getBody().readUtf8().contains("\"parentId\":\"" + parentId.toString() + "\""),
                "init request body should contain parentId");
    }

    @Test
    void initSurvey_postsToSurveysAndReturnsIds() throws Exception {
        UUID parentId = UUID.randomUUID();
        UUID analyzeId = UUID.randomUUID();
        UUID uploadId = UUID.randomUUID();
        mockServer.enqueue(new MockResponse()
                .setResponseCode(201)
                .setBody(String.format(
                        "{\"parent_id\":\"%s\",\"submission_timestamp\":\"2026-05-20T12:00:00Z\","
                                + "\"analyze_sub_job_id\":\"%s\",\"upload_sub_job_id\":\"%s\"}",
                        parentId, analyzeId, uploadId)));

        UUID idemp = UUID.randomUUID();
        DirectUploadService.InitSurveyResponse response = service.initSurvey(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                new DirectUploadService.InitSurveyRequest("INVENTORY_SURVEY", "v1", null),
                idemp,
                "spice-labs-cli/test");

        assertEquals(parentId, response.parentId());
        assertEquals(analyzeId, response.analyzeSubJobId());
        assertEquals(uploadId, response.uploadSubJobId());
        assertEquals(Instant.parse("2026-05-20T12:00:00Z"), response.submissionTimestamp());

        RecordedRequest req = mockServer.takeRequest();
        assertEquals("/api/global/v1/surveys", req.getPath());
        assertEquals("Bearer test-jwt", req.getHeader("Authorization"));
        assertEquals(idemp.toString(), req.getHeader("Idempotency-Key"));
        assertEquals("spice-labs-cli/test", req.getHeader("User-Agent"));
        assertTrue(req.getBody().readUtf8().contains("\"jobType\":\"INVENTORY_SURVEY\""));
    }

    @Test
    void publishStatus_postsToStatusEndpoint() throws Exception {
        mockServer.enqueue(new MockResponse().setResponseCode(204));

        UUID parentId = UUID.randomUUID();
        UUID subJobId = UUID.randomUUID();
        UUID idemp = UUID.randomUUID();
        service.publishStatus(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "jwt",
                parentId,
                subJobId,
                "RUNNING",
                42,
                "uploading",
                idemp,
                "spice-labs-cli/test");

        RecordedRequest req = mockServer.takeRequest();
        assertEquals("/api/global/v1/surveys/" + parentId + "/status", req.getPath());
        assertEquals(idemp.toString(), req.getHeader("Idempotency-Key"));
        assertEquals("spice-labs-cli/test", req.getHeader("User-Agent"));
        String body = req.getBody().readUtf8();
        assertTrue(body.contains("\"subJobId\":\"" + subJobId + "\""));
        assertTrue(body.contains("\"status\":\"RUNNING\""));
        assertTrue(body.contains("\"progress\":42"));
    }

    @Test
    void publishStatus_404IsSilent() {
        mockServer.enqueue(new MockResponse().setResponseCode(404));

        // Should not throw — best-effort progress reporting.
        service.publishStatus(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "jwt",
                UUID.randomUUID(),
                UUID.randomUUID(),
                "RUNNING",
                10,
                null,
                UUID.randomUUID(),
                null);
    }

    @Test
    void publishStatus_transportErrorIsSilent() {
        // Server is down — point at an unroutable URL on this host that won't connect.
        service.publishStatus(
                "http://127.0.0.1:1/api/v1/bundle/upload",
                "jwt",
                UUID.randomUUID(),
                UUID.randomUUID(),
                "RUNNING",
                null,
                null,
                null,
                null);
        // Reaching this line == no exception thrown.
    }

    @Test
    void initSurvey_requiresIdempotencyKey() {
        assertThrows(IllegalArgumentException.class, () -> service.initSurvey(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "jwt",
                new DirectUploadService.InitSurveyRequest("INVENTORY_SURVEY", null, null),
                null,
                null));
    }

    @Test
    void uploadDirect_userAgent_sentOnRequests() throws Exception {
        String presignedUrl = storageServer.url("/upload").toString();
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(buildInitResponse("b", "u", "external/p/b.blob", presignedUrl)));
        storageServer.enqueue(new MockResponse().setResponseCode(200).addHeader("ETag", "\"e\""));
        enqueueCompleteResponse("{\"status\":\"completed\",\"bundleId\":\"b\",\"message\":\"ok\"}");

        DirectUploadService.UploadOptions opts = new DirectUploadService.UploadOptions(
                null, null, null, null, null, "spice-labs-cli/1.2.3");
        service.uploadDirect(
                mockServer.url("/api/global/v1/bundle/upload").toString(),
                "test-jwt",
                null,
                testBundle,
                "test.bin",
                null,
                opts);

        boolean initUA = false;
        boolean completeUA = false;
        RecordedRequest req;
        while ((req = mockServer.takeRequest(1, TimeUnit.SECONDS)) != null) {
            if (req.getPath().endsWith("/init")) {
                initUA = "spice-labs-cli/1.2.3".equals(req.getHeader("User-Agent"));
            } else if (req.getPath().endsWith("/complete")) {
                completeUA = "spice-labs-cli/1.2.3".equals(req.getHeader("User-Agent"));
            }
        }
        assertTrue(initUA, "init request should carry User-Agent");
        assertTrue(completeUA, "complete request should carry User-Agent");
    }

}
