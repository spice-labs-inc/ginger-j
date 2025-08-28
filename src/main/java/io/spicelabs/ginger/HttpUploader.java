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
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class HttpUploader {
  private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(HttpUploader.class);
  private static final OkHttpClient CLIENT = new OkHttpClient()
      .newBuilder()
      .writeTimeout(5, TimeUnit.MINUTES)
      .readTimeout(5, TimeUnit.MINUTES)
      .build();

  public static void upload(String serverUrl, String jwt, File bundle) throws IOException {
    MediaType mediaType = MediaType.parse("application/zip");
    RequestBody body = RequestBody.create(bundle, mediaType);

    Request request = new Request.Builder()
        .url(serverUrl)
        .addHeader("Authorization", "Bearer " + jwt)
        .post(body)
        .build();

    log.info("Starting bundle upload ({} bytes) to {}", bundle.length(), serverUrl);
    try (Response resp = CLIENT.newCall(request).execute()) {
      if (resp.isSuccessful()) {
        log.info("Successfully sent bundle");
      } else {
        String msg = resp.body() != null ? resp.body().string() : "no response body";
        throw new IOException("Upload failed: " + resp.code() + " " + msg);
      }
    }
  }
}
