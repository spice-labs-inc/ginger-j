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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

public class Validators {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static void validateDeployEvents(Path path) throws Exception {
    try (Stream<Path> stream = java.nio.file.Files.walk(path)) {
      boolean found = stream.filter(p -> p.toString().endsWith(".json"))
          .anyMatch(p -> {
            try {
              JsonNode node = MAPPER.readTree(p.toFile());
              if (isValidDeploy(node)) {
                return true;
              }
            } catch (java.io.IOException ignore) {
              // ignore
            }
            return false;
          });

      if (!found) throw new IllegalArgumentException("No valid deploy-event JSON found");
    }
  }

  private static boolean isValidDeploy(JsonNode n) {
    return n.hasNonNull("identifier")
        && n.hasNonNull("system")
        && n.hasNonNull("artifact")
        && (n.hasNonNull("start_time") || n.hasNonNull("end_time"));
  }

  public static void validateClusters(Path path) throws Exception {
    Set<String> extensions = new HashSet<>();
    try (Stream<Path> stream = Files.walk(path)) {
      stream.filter(Files::isRegularFile)
          .forEach(p -> {
            String e = p.toString();
            if (e.endsWith(".grc")) extensions.add("grc");
            if (e.endsWith(".grd")) extensions.add("grd");
            if (e.endsWith(".gri")) extensions.add("gri");
          });
      if (!(extensions.containsAll(List.of("grc", "grd", "gri"))))
        throw new IllegalArgumentException("Must have all of .grc, .grd, .gri");
    }
  }
}
