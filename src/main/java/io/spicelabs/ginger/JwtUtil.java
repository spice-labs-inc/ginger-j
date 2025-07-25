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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;

public class JwtUtil {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static JsonNode decodePayload(String jwt) throws Exception {
    String[] parts = jwt.split("\\.");
    if (parts.length < 2) {
      throw new IllegalArgumentException("Invalid JWT");
    }
    byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
    return MAPPER.readTree(decoded);
  }

  public static String getStringClaim(JsonNode payload, String key) {
    JsonNode n = payload.get(key);
    return (n != null && n.isTextual()) ? n.asText() : null;
  }

  public static long getLongClaim(JsonNode payload, String key) {
    JsonNode n = payload.get(key);
    return (n != null && n.isNumber()) ? n.asLong() : -1;
  }
}
