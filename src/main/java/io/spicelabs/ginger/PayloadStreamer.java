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

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public class PayloadStreamer {
  public static InputStream stream(Path payload) throws IOException {
    if (Files.isDirectory(payload)) {
      PipedOutputStream pos = new PipedOutputStream();
      PipedInputStream pis = new PipedInputStream(pos, 64 * 1024); // 64 KB buffer
      Thread thread = new Thread(() -> {
        try (TarArchiveOutputStream taos = new TarArchiveOutputStream(pos)) {
          try (Stream<Path> stream = Files.walk(payload)) {
            stream.filter(Files::isRegularFile)
                .forEach(p -> {
                  try {
                    String entryName = payload.relativize(p).toString();
                    TarArchiveEntry entry = new TarArchiveEntry(p.toFile(), entryName);
                    taos.putArchiveEntry(entry);
                    Files.copy(p, taos);
                    taos.closeArchiveEntry();
                  } catch (IOException e) {
                    throw new UncheckedIOException(e);
                  }
                });
          }
          taos.finish();
        } catch (IOException e) {
          throw new UncheckedIOException(e);
        }
      });

      thread.start();
      return pis;
    } else {
      return Files.newInputStream(payload);
    }
  }
}
