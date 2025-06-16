package io.spicelabs.ginger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Path;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.*;

class ZipBuilderTest {
  @Test
  void entries(@TempDir Path tempDir) throws Exception {
    byte[] data = "data".getBytes();

    try (MockedStatic<CryptoUtil> cryptoMock = Mockito.mockStatic(CryptoUtil.class)) {
      // Stub AES key generation
      cryptoMock.when(CryptoUtil::generateAesKey).thenReturn(new byte[32]);
      // Stub RSA encryption to avoid InvalidKeySpec
      cryptoMock.when(() -> CryptoUtil.encryptWithRsa(Mockito.anyString(), Mockito.any()))
          .thenReturn(new byte[]{0, 1, 2});
      // Stub IV generation
      cryptoMock.when(CryptoUtil::generateIv).thenReturn(new byte[12]);
      // Stub AES GCM encrypt to write dummy data
      cryptoMock.when(() -> CryptoUtil.aesGcmEncrypt(
              Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
          .thenAnswer(invocation -> {
            java.io.OutputStream out = invocation.getArgument(3);
            out.write(new byte[]{9, 9, 9});
            return null;
          });

      File zip = ZipBuilder.build(
          "u", "pem",
          new ByteArrayInputStream(data),
          false,
          "application/x",
          null,
          tempDir
      );

      try (ZipFile zf = new ZipFile(zip)) {
        assertNotNull(zf.getEntry("uuid.txt"));
        assertNotNull(zf.getEntry("key.txt"));
        assertNotNull(zf.getEntry("payload.enc"));
      }
    }
  }
}
