package io.spicelabs.ginger;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.security.SecureRandom;
import java.io.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilTest {
  @Test
  void aesGcmEncryptProducesData() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    byte[] key = CryptoUtil.generateAesKey();
    byte[] iv = CryptoUtil.generateIv();
    byte[] plain = "hi".getBytes();
    var in = new ByteArrayInputStream(plain);
    var out = new ByteArrayOutputStream();
    CryptoUtil.aesGcmEncrypt(key, iv, in, out);
    assertTrue(out.size() > plain.length);
  }

  @Test
  void testLargeEncryption() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    Path temp = Files.createTempFile("ginger_", ".test");
    try {
      OutputStream fos = new FileOutputStream(temp.toFile());
      byte[] bytes = new byte[4096];
SecureRandom r1 = new SecureRandom();


for (int x = 0; x < 2000000; x++) {
  r1.nextBytes(bytes);
  fos.write(bytes);
}

fos.flush();
fos.close();
    byte[] key = CryptoUtil.generateAesKey();
    byte[] iv = CryptoUtil.generateIv();
    Path tempOut = Files.createTempFile("ginger_", ".test");

    try {
      fos = new FileOutputStream(tempOut.toFile());
      InputStream fis = new FileInputStream(temp.toFile());
      CryptoUtil.aesGcmEncrypt(key, iv, fis, fos);
      fos.flush();
      fos.close();
      // the output should be longer than the input
      assertTrue(temp.toFile().length() < tempOut.toFile().length());
    } finally {
      tempOut.toFile().delete();
    }

    } finally {
      temp.toFile().delete();
    }
  }
}