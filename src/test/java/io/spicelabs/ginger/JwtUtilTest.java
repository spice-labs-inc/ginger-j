package io.spicelabs.ginger;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {
  @Test
  void decodePayload() throws Exception {
    String payload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString("{\"k\":\"v\"}".getBytes());
    JsonNode n = JwtUtil.decodePayload("h." + payload + ".s");
    assertEquals("v", n.get("k").asText());
  }
}