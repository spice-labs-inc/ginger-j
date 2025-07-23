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
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public class PayloadStreamer {
  public static InputStream stream(Path payload) throws IOException {
    if (Files.isDirectory(payload)) {
      PipedOutputStream pos = new PipedOutputStream();
      PipedInputStream pis = new PipedInputStream(pos, 64 * 1024); // 64 KB buffer

      final Throwable[] error = new Throwable[1];
      final Thread[] threadRef = new Thread[1];

      Thread thread = new Thread(() -> {
        try (TarArchiveOutputStream taos = new TarArchiveOutputStream(pos)) {
          taos.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
          try (Stream<Path> stream = Files.walk(payload)) {
            stream.filter(Files::isRegularFile)
                .forEach(p -> {
                  try {
                    String entryName = payload.relativize(p).toString();
                    TarArchiveEntry entry = new TarArchiveEntry(entryName);
                    entry.setSize(Files.size(p));
                    taos.putArchiveEntry(entry);
                    Files.copy(p, taos);
                    taos.closeArchiveEntry();
                  } catch (Throwable e) {
                    error[0] = e;
                    throw new RuntimeException(e); // terminate stream
                  }
                });
          }
          taos.finish();
        } catch (Throwable e) {
          error[0] = e;
        } finally {
          try {
            pos.close();
          } catch (IOException ignored) {
          }
        }
      });

      threadRef[0] = thread;
      thread.start();

      return new InputStream() {
        @Override
        public int read() throws IOException {
          int r = pis.read();
          if (r == -1 && error[0] != null)
            throw new PayloadStreamerException(error[0]);
          return r;
        }

        @Override
        public int read(@NotNull byte[] b, int off, int len) throws IOException {
          int r = pis.read(b, off, len);
          if (r == -1 && error[0] != null)
            throw new PayloadStreamerException(error[0]);
          return r;
        }

        @Override
        public void close() throws IOException {
          try {
            threadRef[0].join(); // wait for stream thread to finish
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          pis.close();
          if (error[0] != null)
            throw new PayloadStreamerException(error[0]);
        }
      };
    } else {
      return Files.newInputStream(payload);
    }
  }

  public static class PayloadStreamerException extends RuntimeException {
    public PayloadStreamerException(Throwable cause) {
      super(cause);
    }
  }

}
