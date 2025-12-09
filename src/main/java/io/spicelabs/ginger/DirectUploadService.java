// SPDX-License-Identifier: Apache-2.0
/* Copyright 2025 Spice Labs, Inc. & Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

package io.spicelabs.ginger;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.Buffer;
import okio.BufferedSink;
import okio.ForwardingSink;
import okio.Okio;

/**
 * Service for direct upload flow: init -> upload to presigned URL -> complete.
 * This bypasses the legacy streaming upload through daikon.
 */
public class DirectUploadService {
    private static final Logger log = LoggerFactory.getLogger(DirectUploadService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private static final int MAX_RETRIES = 3;
    private static final long INITIAL_BACKOFF_MS = 1000;

    private static final OkHttpClient DEFAULT_CLIENT = new OkHttpClient()
            .newBuilder()
            .writeTimeout(10, TimeUnit.MINUTES)
            .readTimeout(5, TimeUnit.MINUTES)
            .connectTimeout(30, TimeUnit.SECONDS)
            .build();

    private static final MediaType JSON = MediaType.parse("application/json");
    private static final MediaType OCTET_STREAM = MediaType.parse("application/octet-stream");

    private final OkHttpClient client;

    /**
     * Creates a DirectUploadService with the default HTTP client.
     */
    public DirectUploadService() {
        this(DEFAULT_CLIENT);
    }

    /**
     * Creates a DirectUploadService with a custom HTTP client.
     * Primarily used for testing.
     *
     * @param client the OkHttpClient to use for requests
     */
    public DirectUploadService(OkHttpClient client) {
        this.client = client;
    }

    /**
     * Result of the init request.
     */
    public record InitResponse(
            String presignedUrl,
            String uploadToken,
            int expiresIn,
            String bundleId
    ) {}

    /**
     * Result of the complete request.
     */
    public record CompleteResponse(
            String status,
            String bundleId,
            String message
    ) {}

    /**
     * Request body for init endpoint.
     */
    private record InitRequest(
            String sha256,
            long sizeBytes,
            String filename,
            String encryptedChallenge
    ) {}

    /**
     * Request body for complete endpoint.
     */
    private record CompleteRequest(
            String uploadToken,
            String sha256
    ) {}

    /**
     * Performs the complete direct upload flow:
     * 1. Call /init to get presigned URL
     * 2. Upload directly to storage
     * 3. Call /complete to finalize
     *
     * @param baseUrl    The upload server URL (from x-upload-server claim). /init and /complete are appended to this.
     * @param jwt        The spice pass JWT
     * @param publicKeyPem The RSA public key PEM (for encrypting challenge), or null if no challenge is provided
     * @param bundle     The encrypted bundle file
     * @param filename   Original filename (optional)
     * @param challenge  The x-challenge claim value (may be null for old JWTs)
     */
    public void uploadDirect(
            String baseUrl,
            String jwt,
            String publicKeyPem,
            File bundle,
            String filename,
            String challenge
    ) throws IOException {
        String sha256;
        try {
            sha256 = HashUtil.sha256Hex(bundle);
        } catch (Exception e) {
            throw new IOException("Failed to compute SHA256 hash", e);
        }
        long sizeBytes = bundle.length();

        String hostname;
        try {
            hostname = new java.net.URL(baseUrl).getHost();
        } catch (Exception e) {
            hostname = baseUrl;
        }
        boolean hasChallenge = challenge != null && !challenge.isBlank();
        log.info("Using direct upload to {} with encryption challenge verification: {}",
                hostname, hasChallenge ? "enabled" : "disabled");
        log.info("Starting direct upload: {} bytes, SHA256: {}", sizeBytes, sha256);

        // Step 1: Initialize upload
        InitResponse initResponse = initUpload(baseUrl, jwt, publicKeyPem, sha256, sizeBytes, filename, challenge);
        String presignedUrl = initResponse.presignedUrl();
        String urlPreview = presignedUrl == null ? "null"
                : presignedUrl.length() > 50 ? presignedUrl.substring(0, 50) + "..." : presignedUrl;
        log.info("Init response: presignedUrl={}, bundleId={}", urlPreview, initResponse.bundleId());

        // Step 2: Upload directly to storage
        uploadToStorage(initResponse.presignedUrl(), bundle);
        log.info("Upload to storage complete");

        // Step 3: Complete the upload
        CompleteResponse completeResponse = completeUpload(baseUrl, jwt, initResponse.uploadToken(), sha256);
        log.info("Upload complete: status={}, bundleId={}, sha256={}",
                completeResponse.status(), completeResponse.bundleId(), sha256);
    }

    /**
     * Step 1: Call /init on the upload server
     */
    private InitResponse initUpload(
            String baseUrl,
            String jwt,
            String publicKeyPem,
            String sha256,
            long sizeBytes,
            String filename,
            String challenge
    ) throws IOException {
        String url = normalizeUrl(baseUrl) + "/init";

        String encryptedChallenge = null;
        if (challenge != null && !challenge.isEmpty()) {
            if (publicKeyPem == null || publicKeyPem.isEmpty()) {
                throw new IOException("Public key is required to encrypt the challenge");
            }
            try {
                byte[] encrypted = CryptoUtil.encryptWithRsa(publicKeyPem, challenge.getBytes(StandardCharsets.UTF_8));
                encryptedChallenge = Base64.getEncoder().encodeToString(encrypted);
            } catch (Exception e) {
                throw new IOException("Failed to encrypt challenge", e);
            }
        }

        InitRequest initRequest = new InitRequest(
                sha256,
                sizeBytes,
                (filename != null && !filename.isEmpty()) ? filename : null,
                encryptedChallenge
        );

        String jsonBody;
        try {
            jsonBody = MAPPER.writeValueAsString(initRequest);
        } catch (Exception e) {
            throw new IOException("Failed to serialize init request", e);
        }

        log.debug("Calling init endpoint: {}", url);

        Supplier<Request> requestSupplier = () -> new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + jwt)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(jsonBody, JSON))
                .build();

        try (Response response = executeWithRetry(requestSupplier, "Init upload")) {
            String responseBody = response.body() != null ? response.body().string() : "";
            if (!response.isSuccessful()) {
                throw new IOException("Failed to initialize direct upload: " + response.code() + " " + responseBody);
            }

            JsonNode node = MAPPER.readTree(responseBody);
            JsonNode presignedUrlNode = node.get("presignedUrl");
            JsonNode uploadTokenNode = node.get("uploadToken");
            JsonNode bundleIdNode = node.get("bundleId");

            List<String> missingFields = new ArrayList<>();
            if (presignedUrlNode == null) missingFields.add("presignedUrl");
            if (uploadTokenNode == null) missingFields.add("uploadToken");
            if (bundleIdNode == null) missingFields.add("bundleId");
            if (!missingFields.isEmpty()) {
                throw new IOException("Init response missing required field(s): " + String.join(", ", missingFields));
            }

            return new InitResponse(
                    presignedUrlNode.asText(),
                    uploadTokenNode.asText(),
                    node.has("expiresIn") ? node.get("expiresIn").asInt() : 3600,
                    bundleIdNode.asText()
            );
        }
    }

    /**
     * Step 2: Upload directly to the presigned URL
     */
    private void uploadToStorage(String presignedUrl, File bundle) throws IOException {
        log.info("Uploading {} to Spice Labs Secure Project Storage...", formatBytes(bundle.length()));

        // Create fresh RequestBody for each retry attempt (file-backed bodies can be re-read)
        Supplier<Request> requestSupplier = () -> {
            RequestBody fileBody = RequestBody.create(bundle, OCTET_STREAM);
            RequestBody body = new ProgressRequestBody(fileBody, bundle.length());
            return new Request.Builder()
                    .url(presignedUrl)
                    .put(body)
                    .addHeader("Content-Type", "application/octet-stream")
                    .build();
        };

        try (Response response = executeWithRetry(requestSupplier, "Storage upload")) {
            if (!response.isSuccessful()) {
                String responseBody = response.body() != null ? response.body().string() : "";
                throw new IOException("Storage upload failed: " + response.code() + " " + responseBody);
            }
        }
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private static class ProgressRequestBody extends RequestBody {
        /** Percentage interval between full progress reports (e.g., 20 = report every 20%) */
        private static final int PROGRESS_INTERVAL_PERCENT = 20;
        /** Percentage interval between dot outputs (e.g., 2 = dot every 2%) */
        private static final int DOT_INTERVAL_PERCENT = 2;
        private final RequestBody delegate;
        private final long totalBytes;
        private volatile int lastReportedStep = -1;
        private volatile int lastDotPercent = -1;
        private volatile long lastReportedBytes = 0;
        private volatile long lastReportedTimeMs = 0;
        private volatile long uploadStartTimeMs = 0;

        ProgressRequestBody(RequestBody delegate, long totalBytes) {
            this.delegate = delegate;
            this.totalBytes = totalBytes;
        }

        @Override
        public MediaType contentType() {
            return delegate.contentType();
        }

        @Override
        public long contentLength() throws IOException {
            return delegate.contentLength();
        }

        @Override
        public void writeTo(BufferedSink sink) throws IOException {
            BufferedSink progressSink = Okio.buffer(new ForwardingSink(sink) {
                private long bytesWritten = 0;

                @Override
                public void write(Buffer source, long byteCount) throws IOException {
                    super.write(source, byteCount);
                    bytesWritten += byteCount;
                    reportProgress(bytesWritten);
                }
            });
            delegate.writeTo(progressSink);
            progressSink.flush();
        }

        private void reportProgress(long bytesWritten) {
            // Initialize timing on first call (when upload actually starts)
            if (uploadStartTimeMs == 0) {
                uploadStartTimeMs = System.currentTimeMillis();
                lastReportedTimeMs = uploadStartTimeMs;
            }

            if (totalBytes == 0) {
                if (lastReportedStep < 0) {
                    lastReportedStep = 0;
                    log.info("Upload progress: 100% (0 B / 0 B)");
                }
                return;
            }
            int percent = (int) ((bytesWritten * 100) / totalBytes);

            // Print dot every 2% (without newline) for visual feedback
            int dotStep = percent / DOT_INTERVAL_PERCENT;
            if (dotStep > lastDotPercent) {
                lastDotPercent = dotStep;
                System.out.print(".");
                System.out.flush();
            }

            // Print full progress line every 20%
            int step = percent / PROGRESS_INTERVAL_PERCENT;
            if (step > lastReportedStep) {
                long now = System.currentTimeMillis();
                long elapsedMs = now - lastReportedTimeMs;
                long bytesSinceLastReport = bytesWritten - lastReportedBytes;

                // Calculate instantaneous speed for this interval
                String intervalSpeed = elapsedMs > 0
                        ? formatBytes((bytesSinceLastReport * 1000) / elapsedMs) + "/s"
                        : "N/A";

                // Calculate overall average speed since upload started
                long totalElapsedMs = now - uploadStartTimeMs;
                String avgSpeed = totalElapsedMs > 0
                        ? formatBytes((bytesWritten * 1000) / totalElapsedMs) + "/s"
                        : "N/A";

                lastReportedStep = step;
                lastReportedBytes = bytesWritten;
                lastReportedTimeMs = now;

                // Print newline before log message to separate from dots
                System.out.println();
                log.info("Upload progress: {}% ({} / {}) @ {} (avg: {})",
                        percent, formatBytes(bytesWritten), formatBytes(totalBytes), intervalSpeed, avgSpeed);
            }
        }
    }

    /**
     * Step 3: Call /complete on the upload server
     */
    private CompleteResponse completeUpload(
            String baseUrl,
            String jwt,
            String uploadToken,
            String sha256
    ) throws IOException {
        String url = normalizeUrl(baseUrl) + "/complete";

        CompleteRequest completeRequest = new CompleteRequest(uploadToken, sha256);
        String jsonBody;
        try {
            jsonBody = MAPPER.writeValueAsString(completeRequest);
        } catch (Exception e) {
            throw new IOException("Failed to serialize complete request", e);
        }

        log.debug("Calling complete endpoint: {}", url);

        Supplier<Request> requestSupplier = () -> new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + jwt)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(jsonBody, JSON))
                .build();

        try (Response response = executeWithRetry(requestSupplier, "Complete upload")) {
            String responseBody = response.body() != null ? response.body().string() : "";
            if (!response.isSuccessful()) {
                throw new IOException("Failed to complete direct upload: " + response.code() + " " + responseBody);
            }

            JsonNode node = MAPPER.readTree(responseBody);
            return new CompleteResponse(
                    node.has("status") ? node.get("status").asText() : "unknown",
                    node.has("bundleId") ? node.get("bundleId").asText() : null,
                    node.has("message") ? node.get("message").asText() : null
            );
        }
    }

    /**
     * Normalize URL by removing trailing slash.
     */
    private static String normalizeUrl(String url) {
        if (url != null && url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }

    /**
     * Execute a request with retry logic and exponential backoff.
     * Retries on 5xx errors and network failures.
     * Uses a Supplier to create fresh requests for each retry attempt (required for requests with bodies).
     * Note: Caller is responsible for closing the returned Response.
     */
    private Response executeWithRetry(Supplier<Request> requestSupplier, String operationName) throws IOException {
        IOException lastException = null;
        long backoffMs = INITIAL_BACKOFF_MS;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            Response response = null;
            try {
                response = client.newCall(requestSupplier.get()).execute();

                // Don't retry on client errors (4xx) - those won't change
                if (response.isSuccessful() || (response.code() >= 400 && response.code() < 500)) {
                    return response;
                }

                // Server error (5xx) - read body before closing, then retry
                String body = response.body() != null ? response.body().string() : "";
                int code = response.code();
                response.close();
                response = null;

                if (attempt < MAX_RETRIES) {
                    log.warn("{} failed with {} (attempt {}/{}), retrying in {}ms: {}",
                            operationName, code, attempt, MAX_RETRIES, backoffMs, body);
                    TimeUnit.MILLISECONDS.sleep(backoffMs);
                    backoffMs *= 2; // Exponential backoff
                } else {
                    throw new IOException(operationName + " failed after " + MAX_RETRIES +
                            " attempts: " + code + " " + body);
                }
            } catch (IOException e) {
                if (response != null) {
                    response.close();
                }
                lastException = e;
                if (attempt < MAX_RETRIES) {
                    log.warn("{} failed (attempt {}/{}), retrying in {}ms: {}",
                            operationName, attempt, MAX_RETRIES, backoffMs, e.getMessage());
                    try {
                        TimeUnit.MILLISECONDS.sleep(backoffMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during retry", ie);
                    }
                    backoffMs *= 2;
                }
            } catch (InterruptedException e) {
                if (response != null) {
                    response.close();
                }
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during retry", e);
            }
        }

        throw lastException != null ? lastException :
                new IOException(operationName + " failed after " + MAX_RETRIES + " attempts");
    }
}
