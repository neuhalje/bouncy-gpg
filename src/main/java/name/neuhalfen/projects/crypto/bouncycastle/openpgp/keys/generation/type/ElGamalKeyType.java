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

import java.security.spec.AlgorithmParameterSpec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeyAlgorithm;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.ElGamalLength;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

public class ElGamalKeyType implements KeyType {

  private final ElGamalLength length;

  ElGamalKeyType(ElGamalLength length) {
    requireNonNull(length, "length cannot be null");
    this.length = length;
  }

  public static ElGamalKeyType withLength(ElGamalLength length) {
    requireNonNull(length, "length cannot be null");
    return new ElGamalKeyType(length);
  }

  @Override
  public String getName() {
    return "ElGamal";
  }

  @Override
  public PublicKeyAlgorithm getAlgorithm() {
    return PublicKeyAlgorithm.ELGAMAL_GENERAL;
  }

  @Override
  public AlgorithmParameterSpec getAlgorithmSpec() {
    return new ElGamalParameterSpec(length.getP(), length.getG());
  }
}
