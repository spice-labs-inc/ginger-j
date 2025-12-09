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
import java.io.RandomAccessFile;
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
        int lastReportedPercent = -1;

        ExecutorService executor = Executors.newFixedThreadPool(Math.min(PARALLEL_UPLOADS, parts.size()));
        List<Future<?>> futures = new ArrayList<>();

        for (PartInfo part : parts) {
            futures.add(executor.submit(() -> {
                try {
                    String etag = uploadPart(bundle, part, totalSize, totalBytesUploaded,
                            startTime, lastProgressTime, lastProgressBytes);
                    etags.put(part.partNumber(), etag);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to upload part " + part.partNumber(), e);
                }
            }));
        }

        executor.shutdown();
        try {
            for (Future<?> future : futures) {
                future.get();
            }
        } catch (Exception e) {
            executor.shutdownNow();
            throw new IOException("Part upload failed", e.getCause());
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
            AtomicLong lastProgressBytes
    ) throws IOException {
        byte[] data = new byte[(int) part.size()];
        try (RandomAccessFile raf = new RandomAccessFile(bundle, "r")) {
            raf.seek(part.offset());
            raf.readFully(data);
        }

        Supplier<Request> requestSupplier = () -> new Request.Builder()
                .url(part.presignedUrl())
                .put(RequestBody.create(data, OCTET_STREAM))
                .addHeader("Content-Type", "application/octet-stream")
                .build();

        try (Response response = executeWithRetry(requestSupplier, "Part " + part.partNumber())) {
            if (!response.isSuccessful()) {
                String body = response.body() != null ? response.body().string() : "";
                throw new IOException("Part upload failed: " + response.code() + " " + body);
            }

            String etag = response.header("ETag");
            if (etag == null) {
                throw new IOException("No ETag in response for part " + part.partNumber());
            }

            long uploaded = totalBytesUploaded.addAndGet(part.size());
            reportProgress(uploaded, totalSize, startTime, lastProgressTime, lastProgressBytes);

            return etag.replace("\"", "");
        }
    }

    private synchronized void reportProgress(
            long bytesUploaded,
            long totalSize,
            long startTime,
            AtomicLong lastProgressTime,
            AtomicLong lastProgressBytes
    ) {
        int percent = (int) ((bytesUploaded * 100) / totalSize);
        int step = percent / 10;

        System.out.print(".");
        System.out.flush();

        if (step > 0 && step % 2 == 0) {
            long now = System.currentTimeMillis();
            long elapsed = now - startTime;
            String avgSpeed = elapsed > 0 ? formatBytes((bytesUploaded * 1000) / elapsed) + "/s" : "N/A";

            long intervalElapsed = now - lastProgressTime.get();
            long intervalBytes = bytesUploaded - lastProgressBytes.get();
            String intervalSpeed = intervalElapsed > 0
                    ? formatBytes((intervalBytes * 1000) / intervalElapsed) + "/s"
                    : "N/A";

            lastProgressTime.set(now);
            lastProgressBytes.set(bytesUploaded);

            System.out.println();
            log.info("Upload progress: {}% ({} / {}) @ {} (avg: {})",
                    percent, formatBytes(bytesUploaded), formatBytes(totalSize), intervalSpeed, avgSpeed);
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
        IOException lastException = null;
        long backoffMs = INITIAL_BACKOFF_MS;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            Response response = null;
            try {
                response = client.newCall(requestSupplier.get()).execute();

                if (response.isSuccessful() || (response.code() >= 400 && response.code() < 500)) {
                    return response;
                }

                String body = response.body() != null ? response.body().string() : "";
                int code = response.code();
                response.close();
                response = null;

                if (attempt < MAX_RETRIES) {
                    log.warn("{} failed with {} (attempt {}/{}), retrying in {}ms",
                            operationName, code, attempt, MAX_RETRIES, backoffMs);
                    TimeUnit.MILLISECONDS.sleep(backoffMs);
                    backoffMs *= 2;
                } else {
                    throw new IOException(operationName + " failed after " + MAX_RETRIES + " attempts: " + code);
                }
            } catch (IOException e) {
                if (response != null) response.close();
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
                if (response != null) response.close();
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during retry", e);
            }
        }

        throw lastException != null ? lastException :
                new IOException(operationName + " failed after " + MAX_RETRIES + " attempts");
    }
}
