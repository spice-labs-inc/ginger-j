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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtil {

  private static final String RSA_HEADER = "-----BEGIN PUBLIC KEY-----";
  private static final String RSA_FOOTER = "-----END PUBLIC KEY-----";

  public static byte[] generateAesKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }

  public static byte[] generateIv() {
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    return iv;
  }

  public static byte[] encryptWithRsa(String pem, byte[] data) throws Exception {
    String b64 = pem.replace(RSA_HEADER, "")
        .replace(RSA_FOOTER, "")
        .replaceAll("\\s", "");

    byte[] keyBytes = Base64.getDecoder().decode(b64);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(spec);

    OAEPParameterSpec oaepParams = new OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA256,
        PSource.PSpecified.DEFAULT // Equivalent to Go’s `label = nil`
    );

    Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsa.init(Cipher.ENCRYPT_MODE, pub, oaepParams);
    return rsa.doFinal(data);
  }

  public static void aesGcmEncrypt(byte[] key, byte[] iv,
                                   InputStream in, OutputStream out) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    SecretKeySpec ks = new SecretKeySpec(key, "AES");
    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, ks, spec);

    byte[] buf = new byte[4096], enc;
    int len;
    while ((len = in.read(buf)) != -1) {
      enc = cipher.update(buf, 0, len);
      if (enc != null) out.write(enc);
    }
    enc = cipher.doFinal();
    if (enc != null) out.write(enc);
  }

  public static byte[] randomBytes(int length) throws Exception {
    byte[] bytes = new byte[length];
    java.security.SecureRandom.getInstanceStrong().nextBytes(bytes);
    return bytes;
  }
}
