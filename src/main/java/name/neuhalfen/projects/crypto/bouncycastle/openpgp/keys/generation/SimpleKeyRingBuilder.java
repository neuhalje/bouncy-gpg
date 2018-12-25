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
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public interface SimpleKeyRingBuilder {


  /**
   * Creates a simple RSA KeyPair of length {@code length} with user-id {@code userId}.
   * The KeyPair consists of a single RSA master key which is used for signing, encryption and
   * certification.
   *
   * @param userId user id.
   * @param length length in bits.
   *
   * @return {@link PGPSecretKeyRing} containing the KeyPair.
   *
   * @throws PGPException unspecified error in PGP (not expected)
   * @throws NoSuchAlgorithmException did you call BouncyGPG#registerProvider?
   * @throws NoSuchProviderException did you call BouncyGPG#registerProvider?
   * @throws InvalidAlgorithmParameterException did you call BouncyGPG#registerProvider?
   * @throws IOException IO is dangerous!
   */
  KeyringConfig simpleRsaKeyRing(String userId, RsaLength length)
      throws PGPException, NoSuchAlgorithmException, NoSuchProviderException,
      InvalidAlgorithmParameterException, IOException;


  /**
   * Creates a key ring consisting of an ECDSAKeyType master key and an ECDHKeyType sub-key.
   * The ECDSAKeyType master key is used for signing messages and certifying the sub key.
   * The ECDHKeyType sub-key is used for encryption of messages.
   *
   * @param userId user-id
   *
   * @return {@link PGPSecretKeyRing} containing the key pairs.
   *
   * @throws PGPException unspecified error in PGP (not expected)
   * @throws NoSuchAlgorithmException did you call BouncyGPG#registerProvider?
   * @throws NoSuchProviderException did you call BouncyGPG#registerProvider?
   * @throws InvalidAlgorithmParameterException did you call BouncyGPG#registerProvider?
   * @throws IOException IO is dangerous!
   */
  KeyringConfig simpleEccKeyRing(String userId)
      throws PGPException, NoSuchAlgorithmException, NoSuchProviderException,
      InvalidAlgorithmParameterException, IOException;
}
