package io.spicelabs.ginger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.*;

class ZipBuilderTest {
  @Test
  void entries(@TempDir Path tempDir) throws Exception {
    byte[] data = "data".getBytes(StandardCharsets.UTF_8); // safer

    try (MockedStatic<CryptoUtil> cryptoMock = Mockito.mockStatic(CryptoUtil.class)) {
      // Stub AES key generation
      cryptoMock.when(CryptoUtil::generateAesKey).thenReturn(new byte[32]);

      // Stub RSA encryption
      cryptoMock.when(() -> CryptoUtil.encryptWithRsa(Mockito.anyString(), Mockito.any()))
          .thenReturn(new byte[]{0, 1, 2});

      // Stub IV generation
      cryptoMock.when(CryptoUtil::generateIv).thenReturn(new byte[12]);

      cryptoMock.when(() -> CryptoUtil.randomBytes(Mockito.anyInt()))
          .thenReturn(new byte[128]);


      // Stub AES GCM encryption to write dummy encrypted content
      cryptoMock.when(() -> CryptoUtil.aesGcmEncrypt(
          Mockito.any(),
          Mockito.any(),
          Mockito.any(InputStream.class),
          Mockito.any(OutputStream.class)
      )).thenAnswer(invocation -> {
        OutputStream out = invocation.getArgument(3);
        out.write(new byte[]{9, 9, 9});
        return null;
      });

      File zip = ZipBuilder.build(
          Optional.of("u"), Optional.of("pem"),
          new ByteArrayInputStream(data),
          false,
          "application/x",
          null,
          tempDir,
          BundleFormatVersion.VERSION_1
      );

      try (ZipFile zf = new ZipFile(zip)) {
        assertNotNull(zf.getEntry("uuid.txt"));
        assertNotNull(zf.getEntry("key.txt"));
        assertNotNull(zf.getEntry("payload.enc"));
      }
    }
  }
}
