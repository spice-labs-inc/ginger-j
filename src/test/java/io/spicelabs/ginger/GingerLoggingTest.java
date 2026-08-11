package io.spicelabs.ginger;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;

/**
 * Logging is configurable here the same way it is in every other Spice tool, and — because
 * this class is a library as much as a command — only when it owns the process.
 */
class GingerLoggingTest {

  private static LoggerContext context() {
    return (LoggerContext) LoggerFactory.getILoggerFactory();
  }

  @AfterEach
  void reset() {
    context().getLogger("io.spicelabs.ginger").setLevel(null);
  }

  @Test
  void theFlagSetsThisProgramsLevel() {
    Ginger ginger = new Ginger();
    ginger.logLevel = "debug";

    ginger.applyLogging();

    assertEquals(Level.DEBUG, context().getLogger("io.spicelabs.ginger").getLevel());
  }

  @Test
  void buildingAndRunningAsALibraryDoesNotTouchLogging() {
    // A library that reconfigures the logging of whatever embedded it is a rude surprise:
    // the host chose its levels deliberately. Only main() applies the group.
    context().getLogger("io.spicelabs.ginger").setLevel(Level.WARN);

    Ginger.builder().jwt("irrelevant").uuid("irrelevant");

    assertEquals(
        Level.WARN,
        context().getLogger("io.spicelabs.ginger").getLevel(),
        "the host's level survived");
  }

  @Test
  void aMisspeltLevelIsRefused() {
    Ginger ginger = new Ginger();
    ginger.logLevel = "verbose";

    assertThrows(io.spicelabs.config.ConfigurationException.class, ginger::applyLogging);
  }
}
