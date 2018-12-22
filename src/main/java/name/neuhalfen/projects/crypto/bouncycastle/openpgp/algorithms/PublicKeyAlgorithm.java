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
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

public enum PublicKeyAlgorithm {

  RSA_GENERAL(PublicKeyAlgorithmTags.RSA_GENERAL),
  RSA_ENCRYPT(PublicKeyAlgorithmTags.RSA_ENCRYPT),
  RSA_SIGN(PublicKeyAlgorithmTags.RSA_SIGN),
  ELGAMAL_ENCRYPT(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT),
  DSA(PublicKeyAlgorithmTags.DSA),
  /**
   * EC is deprecated.
   *
   * @deprecated use {@link #ECDH} instead.
   */
  EC(PublicKeyAlgorithmTags.EC),
  ECDH(PublicKeyAlgorithmTags.ECDH),
  ECDSA(PublicKeyAlgorithmTags.ECDSA),
  ELGAMAL_GENERAL(PublicKeyAlgorithmTags.ELGAMAL_GENERAL),
  DIFFIE_HELLMAN(PublicKeyAlgorithmTags.DIFFIE_HELLMAN),
  ;

  private static final Map<Integer, PublicKeyAlgorithm> MAP = new HashMap<>();

  static {
    for (final PublicKeyAlgorithm p : PublicKeyAlgorithm.values()) {
      MAP.put(p.algorithmId, p);
    }
  }

  private final int algorithmId;

  PublicKeyAlgorithm(int algorithmId) {
    this.algorithmId = algorithmId;
  }

  public static PublicKeyAlgorithm fromId(int id) { // NOPMD: ShortVariable
    return MAP.get(id);
  }

  public int getAlgorithmId() {
    return algorithmId;
  }
}
