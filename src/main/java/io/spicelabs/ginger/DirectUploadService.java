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
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.BufferedSink;
import okio.Okio;

public class DirectUploadService {
    private static final Logger log = LoggerFactory.getLogger(DirectUploadService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private static final int MAX_RETRIES = 3;
    private static final long INITIAL_BACKOFF_MS = 1000;
    private static final int PARALLEL_UPLOADS = 4;

    private static final OkHttpClient DEFAULT_CLIENT = new OkHttpClient()
            .newBuilder()
            .writeTimeout(10, TimeUnit.MINUTES)
            .readTimeout(5, TimeUnit.MINUTES)
            .connectTimeout(30, TimeUnit.SECONDS)
            .build();

    private static final MediaType JSON = MediaType.parse("application/json");
    private static final MediaType OCTET_STREAM = MediaType.parse("application/octet-stream");

    private final OkHttpClient client;

    public DirectUploadService() {
        this(DEFAULT_CLIENT);
    }

    public DirectUploadService(OkHttpClient client) {
        this.client = client;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record InitResponse(
            String uploadId,
            String blobKey,
            String bundleId,
            int expiresIn,
            List<PartInfo> parts
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PartInfo(
            int partNumber,
            String presignedUrl,
            long offset,
            long size
    ) {}

    public record CompleteResponse(String status, String bundleId, String message) {}

    private record InitRequest(String sha256, long sizeBytes, String filename, String encryptedChallenge) {}

    private record CompleteRequest(String uploadId, String blobKey, String sha256, List<CompletedPart> parts) {}

    private record CompletedPart(int partNumber, String etag) {}

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

        InitResponse initResponse = initUpload(baseUrl, jwt, publicKeyPem, sha256, sizeBytes, filename, challenge);
        log.info("Initialized multipart upload: {} parts, bundleId={}",
                initResponse.parts().size(), initResponse.bundleId());

        List<CompletedPart> completedParts = uploadParts(bundle, initResponse.parts());

        CompleteResponse completeResponse = completeUpload(
                baseUrl, jwt, initResponse.uploadId(), initResponse.blobKey(), sha256, completedParts);
        log.info("Upload complete: status={}, bundleId={}, sha256={}",
                completeResponse.status(), completeResponse.bundleId(), sha256);
    }

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
                sha256, sizeBytes,
                (filename != null && !filename.isEmpty()) ? filename : null,
                encryptedChallenge
        );

        String jsonBody = MAPPER.writeValueAsString(initRequest);

        Supplier<Request> requestSupplier = () -> new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + jwt)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(jsonBody, JSON))
                .build();

        try (Response response = executeWithRetry(requestSupplier, "Init upload")) {
            String responseBody = response.body() != null ? response.body().string() : "";
            if (!response.isSuccessful()) {
                throw new IOException("Failed to initialize upload: " + response.code() + " " + responseBody);
            }
            return MAPPER.readValue(responseBody, InitResponse.class);
        }
    }

    private List<CompletedPart> uploadParts(File bundle, List<PartInfo> parts) throws IOException {
        long totalSize = bundle.length();
        log.info("Uploading {} to Spice Labs Secure Project Storage...", formatBytes(totalSize));

        AtomicLong totalBytesUploaded = new AtomicLong(0);
        ConcurrentHashMap<Integer, String> etags = new ConcurrentHashMap<>();
        long startTime = System.currentTimeMillis();
        AtomicLong lastProgressTime = new AtomicLong(startTime);
        AtomicLong lastProgressBytes = new AtomicLong(0);
        AtomicLong lastDotStep = new AtomicLong(-1);
        AtomicLong lastLogStep = new AtomicLong(0);

        ExecutorService executor = Executors.newFixedThreadPool(Math.min(PARALLEL_UPLOADS, parts.size()));
        List<Future<?>> futures = new ArrayList<>();

        for (PartInfo part : parts) {
            futures.add(executor.submit(() -> {
                try {
                    String etag = uploadPart(bundle, part, totalSize, totalBytesUploaded,
                            startTime, lastProgressTime, lastProgressBytes, lastDotStep, lastLogStep);
                    etags.put(part.partNumber(), etag);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to upload part " + part.partNumber(), e);
                }
            }));
        }

        executor.shutdown();

        List<Throwable> exceptions = new ArrayList<>();
        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                exceptions.add(cause);
            }
        }

        if (!exceptions.isEmpty()) {
            for (int i = 1; i < exceptions.size(); i++) {
                log.error("Additional part upload failure", exceptions.get(i));
            }
            throw new IOException("Part upload failed", exceptions.get(0));
        }

        System.out.println();
        long elapsed = System.currentTimeMillis() - startTime;
        String avgSpeed = elapsed > 0 ? formatBytes((totalSize * 1000) / elapsed) + "/s" : "N/A";
        log.info("Upload complete: {} in {}s (avg: {})", formatBytes(totalSize), elapsed / 1000, avgSpeed);

        return parts.stream()
                .sorted(Comparator.comparingInt(PartInfo::partNumber))
                .map(p -> new CompletedPart(p.partNumber(), etags.get(p.partNumber())))
                .toList();
    }

    private String uploadPart(
            File bundle,
            PartInfo part,
            long totalSize,
            AtomicLong totalBytesUploaded,
            long startTime,
            AtomicLong lastProgressTime,
            AtomicLong lastProgressBytes,
            AtomicLong lastDotStep,
            AtomicLong lastLogStep
    ) throws IOException {
        long progressIntervalBytes = Math.max(totalSize / 50, 8192); // 2% of total, min 8KB
        AtomicLong attemptBytesUploaded = new AtomicLong(0);

        RequestBody requestBody = new RequestBody() {
            @Override
            public MediaType contentType() {
                return OCTET_STREAM;
            }

            @Override
            public long contentLength() {
                return part.size();
            }

            @Override
            public void writeTo(BufferedSink sink) throws IOException {
                // Reset attempt counter at start of each attempt
                attemptBytesUploaded.set(0);
                try (FileInputStream fis = new FileInputStream(bundle)) {
                    long skipped = fis.skip(part.offset());
                    if (skipped != part.offset()) {
                        throw new IOException("Failed to skip to offset " + part.offset());
                    }
                    byte[] buffer = new byte[8192];
                    long remaining = part.size();
                    long bytesSinceLastUpdate = 0;
                    while (remaining > 0) {
                        int toRead = (int) Math.min(buffer.length, remaining);
                        int read = fis.read(buffer, 0, toRead);
                        if (read == -1) break;
                        sink.write(buffer, 0, read);
                        remaining -= read;
                        bytesSinceLastUpdate += read;

                        if (bytesSinceLastUpdate >= progressIntervalBytes) {
                            long uploaded = totalBytesUploaded.addAndGet(bytesSinceLastUpdate);
                            attemptBytesUploaded.addAndGet(bytesSinceLastUpdate);
                            bytesSinceLastUpdate = 0;
                            reportProgress(uploaded, totalSize, startTime, lastProgressTime, lastProgressBytes, lastDotStep, lastLogStep);
                        }
                    }
                    if (bytesSinceLastUpdate > 0) {
                        long uploaded = totalBytesUploaded.addAndGet(bytesSinceLastUpdate);
                        attemptBytesUploaded.addAndGet(bytesSinceLastUpdate);
                        reportProgress(uploaded, totalSize, startTime, lastProgressTime, lastProgressBytes, lastDotStep, lastLogStep);
                    }
                }
            }
        };

        Runnable onRetry = () -> {
            long bytesToSubtract = attemptBytesUploaded.getAndSet(0);
            if (bytesToSubtract > 0) {
                totalBytesUploaded.addAndGet(-bytesToSubtract);
            }
        };

        Supplier<Request> requestSupplier = () -> new Request.Builder()
                .url(part.presignedUrl())
                .put(requestBody)
                .addHeader("Content-Type", "application/octet-stream")
                .build();

        try (Response response = executeWithRetry(requestSupplier, "Part " + part.partNumber(), onRetry)) {
            if (!response.isSuccessful()) {
                String body = response.body() != null ? response.body().string() : "";
                throw new IOException("Part upload failed: " + response.code() + " " + body);
            }

            String etag = response.header("ETag");
            if (etag == null) {
                throw new IOException("No ETag in response for part " + part.partNumber());
            }

            return etag.replace("\"", "");
        }
    }

    private void reportProgress(
            long bytesUploaded,
            long totalSize,
            long startTime,
            AtomicLong lastProgressTime,
            AtomicLong lastProgressBytes,
            AtomicLong lastDotStep,
            AtomicLong lastLogStep
    ) {
        int percent = (int) ((bytesUploaded * 100) / totalSize);
        int dotStep = percent / 2;  // every 2%
        int logStep = percent / 20; // every 20%

        long prevDotStep = lastDotStep.get();
        if (dotStep > prevDotStep && lastDotStep.compareAndSet(prevDotStep, dotStep)) {
            synchronized (System.out) {
                System.out.print(".");
                System.out.flush();
            }
        }

        long prevLogStep = lastLogStep.get();
        if (logStep > prevLogStep && lastLogStep.compareAndSet(prevLogStep, logStep)) {
            long now = System.currentTimeMillis();
            long elapsed = now - startTime;
            String avgSpeed = elapsed > 0 ? formatBytes((bytesUploaded * 1000) / elapsed) + "/s" : "N/A";

            long prevTime = lastProgressTime.getAndSet(now);
            long prevBytes = lastProgressBytes.getAndSet(bytesUploaded);
            long intervalElapsed = now - prevTime;
            long intervalBytes = bytesUploaded - prevBytes;
            String intervalSpeed = intervalElapsed > 0
                    ? formatBytes((intervalBytes * 1000) / intervalElapsed) + "/s"
                    : "N/A";

            synchronized (System.out) {
                System.out.println();
            }
            log.info("Upload progress: {}% ({} / {}) @ {} (avg: {})",
                    logStep * 20, formatBytes(bytesUploaded), formatBytes(totalSize), intervalSpeed, avgSpeed);
        }
    }

    private CompleteResponse completeUpload(
            String baseUrl,
            String jwt,
            String uploadId,
            String blobKey,
            String sha256,
            List<CompletedPart> parts
    ) throws IOException {
        String url = normalizeUrl(baseUrl) + "/complete";

        CompleteRequest completeRequest = new CompleteRequest(uploadId, blobKey, sha256, parts);
        String jsonBody = MAPPER.writeValueAsString(completeRequest);

        Supplier<Request> requestSupplier = () -> new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + jwt)
                .addHeader("Content-Type", "application/json")
                .post(RequestBody.create(jsonBody, JSON))
                .build();

        try (Response response = executeWithRetry(requestSupplier, "Complete upload")) {
            String responseBody = response.body() != null ? response.body().string() : "";
            if (!response.isSuccessful()) {
                throw new IOException("Failed to complete upload: " + response.code() + " " + responseBody);
            }
            return MAPPER.readValue(responseBody, CompleteResponse.class);
        }
    }

    private static String normalizeUrl(String url) {
        return (url != null && url.endsWith("/")) ? url.substring(0, url.length() - 1) : url;
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private Response executeWithRetry(Supplier<Request> requestSupplier, String operationName) throws IOException {
        return executeWithRetry(requestSupplier, operationName, null);
    }

    private Response executeWithRetry(Supplier<Request> requestSupplier, String operationName, Runnable onRetry) throws IOException {
        IOException lastException = null;
        String lastResponseBody = null;
        int lastCode = 0;
        long backoffMs = INITIAL_BACKOFF_MS;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            Response response = null;
            try {
                response = client.newCall(requestSupplier.get()).execute();

                if (response.isSuccessful() || (response.code() >= 400 && response.code() < 500)) {
                    return response;
                }

                lastResponseBody = response.body() != null ? response.body().string() : "";
                lastCode = response.code();
                response.close();
                response = null;

                if (attempt < MAX_RETRIES) {
                    log.warn("{} failed with {} (attempt {}/{}), retrying in {}ms",
                            operationName, lastCode, attempt, MAX_RETRIES, backoffMs);
                    if (onRetry != null) {
                        onRetry.run();
                    }
                    TimeUnit.MILLISECONDS.sleep(backoffMs);
                    backoffMs *= 2;
                }
            } catch (IOException e) {
                if (response != null) response.close();
                lastException = e;
                if (attempt < MAX_RETRIES) {
                    log.warn("{} failed (attempt {}/{}), retrying in {}ms: {}",
                            operationName, attempt, MAX_RETRIES, backoffMs, e.getMessage());
                    if (onRetry != null) {
                        onRetry.run();
                    }
                    try {
                        TimeUnit.MILLISECONDS.sleep(backoffMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during retry", ie);
                    }
                    backoffMs *= 2;
                }
            } catch (InterruptedException e) {
                if (response != null) response.close();
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during retry", e);
            }
        }

        if (lastException != null) {
            throw lastException;
        }
        throw new IOException(operationName + " failed after " + MAX_RETRIES + " attempts: " + lastCode + " " + lastResponseBody);
    }
}
