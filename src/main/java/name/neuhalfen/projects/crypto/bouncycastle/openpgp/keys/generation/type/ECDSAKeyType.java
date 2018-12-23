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
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type;


import static java.util.Objects.requireNonNull;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeyAlgorithm;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve.EllipticCurve;

@SuppressWarnings("PMD.ShortClassName")
public class ECDSAKeyType extends ECDHKeyType {

  ECDSAKeyType(EllipticCurve curve) {
    super(curve);
  }

  public static ECDSAKeyType fromCurve(EllipticCurve curve) {
    requireNonNull(curve, "curve cannot be null");
    return new ECDSAKeyType(curve);
  }

  @Override
  public String getName() {
    return "ECDSA";
  }

  @Override
  public PublicKeyAlgorithm getAlgorithm() {
    return PublicKeyAlgorithm.ECDSA;
  }
}
