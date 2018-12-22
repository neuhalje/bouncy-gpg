/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.bcpg.sig.Features;

/**
 * Wraps bouncy castles org.bouncycastle.bcpg.sig.Features into an enum.
 *
 * @see Features
 */
public enum Feature {

  /**
   * Add modification detection package.
   *
   * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.14">
   *     RFC-4880 §5.14: Modification Detection Code Packet</a>
   */
  MODIFICATION_DETECTION(Features.FEATURE_MODIFICATION_DETECTION),
  ;

  private static final Map<Byte, Feature> MAP = new HashMap<>();

  static {
    for (final Feature f : Feature.values()) {
      MAP.put(f.featureId, f);
    }
  }


  private final byte featureId;

  Feature(byte featureId) {
    this.featureId = featureId;
  }

  public static Feature fromId(byte id) { // NOPMD: ShortVariable
    return MAP.get(id);
  }

  public byte getFeatureId() {
    return featureId;
  }
}
