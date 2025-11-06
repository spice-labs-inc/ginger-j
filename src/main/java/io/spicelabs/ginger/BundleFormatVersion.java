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

import java.util.Set;

public enum BundleFormatVersion {
  VERSION_1(1, Set.of()),
  VERSION_2(2, Set.of(Feature.COMPRESS_TAR));

  private final int versionNumber;
  private final Set<Feature> features;

  BundleFormatVersion(int versionNumber, Set<Feature> features) {
    this.versionNumber = versionNumber;
    this.features = features;
  }

  public int getVersionNumber() {
    return versionNumber;
  }

  public boolean supports(Feature feature) {
    return features.contains(feature);
  }

  public static BundleFormatVersion fromInt(int version) {
    for (BundleFormatVersion v : values()) {
      if (v.versionNumber == version) {
        return v;
      }
    }
    throw new IllegalArgumentException("Unknown bundle format version: " + version);
  }

  public enum Feature {
    COMPRESS_TAR
  }
}
