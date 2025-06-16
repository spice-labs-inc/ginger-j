package io.spicelabs.ginger;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilTest {
  @Test
  void aesGcmEncryptProducesData() throws Exception {
    byte[] key = CryptoUtil.generateAesKey();
    byte[] iv = CryptoUtil.generateIv();
    byte[] plain = "hi".getBytes();
    var in = new ByteArrayInputStream(plain);
    var out = new ByteArrayOutputStream();
    CryptoUtil.aesGcmEncrypt(key, iv, in, out);
    assertTrue(out.size() > plain.length);
  }
}