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
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.internal;

import static java.util.Objects.requireNonNull;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nullable;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

@SuppressWarnings("PMD.LawOfDemeter")
public final class KeyRingSubKeyFixUtil {

  private static final Logger LOGGER = Logger.getLogger(KeyRingSubKeyFixUtil.class.getName());

  private KeyRingSubKeyFixUtil() {/* Util Class */}

  /**
   * This method makes sure, that sub keys do consist of sub key packets.
   * Bouncycastle versions up to and including 1.60 created {@link PGPSecretKeyRing}s which sub keys
   * consisted of
   * normal public key packets, which would result in lost keys when converting PGPSecretKeyRings to
   * PGPPublicKeyRings.
   *
   * This method throws a {@link RuntimeException} of a {@link NoSuchFieldException} or {@link
   * IllegalAccessException}.
   *
   * @param secretKeys possibly faulty PGPSecretKeyRing
   * @param decryptor decryptor in case the keys are encrypted (can be null)
   * @param encryptor encryptor to re-encrypt the keys in case they are encrypted (can be null)
   *
   * @return fixed PGPSecretKeyRing
   *
   * @throws PGPException in case we cannot dismantle or reassemble the key.
   * @see <a href="https://github.com/bcgit/bc-java/issues/381">Bouncycastle Java bug report #381</a>
   */
  public static PGPSecretKeyRing repairSubkeyPackets(PGPSecretKeyRing secretKeys,
      @Nullable PBESecretKeyDecryptor decryptor,
      @Nullable PBESecretKeyEncryptor encryptor)
      throws PGPException {
    requireNonNull(secretKeys, "secretKeys cannot be null");

    final PGPDigestCalculator calculator = new BcPGPDigestCalculatorProvider()
        .get(HashAlgorithmTags.SHA1);

    final List<PGPSecretKey> fixedSecretKeys = new ArrayList<>();
    final Iterator<PGPSecretKey> secretKeyIterator = secretKeys.iterator();
    try {

      while (secretKeyIterator.hasNext()) {
        final PGPSecretKey secSubKey = secretKeyIterator.next();

        if (secSubKey.isMasterKey()) { // NOPMD: Demeter
          fixedSecretKeys.add(secSubKey);
          continue;
        }

        final PGPPublicKey pubSubKey = secSubKey.getPublicKey();

        // check for public key packet type

        final Field publicPk = pubSubKey.getClass().getDeclaredField("publicPk");
        publicPk.setAccessible(true);
        PublicKeyPacket keyPacket = (PublicKeyPacket) publicPk.get(pubSubKey);

        if (keyPacket instanceof PublicSubkeyPacket) {
          // Sub key is already sub key
          fixedSecretKeys.add(secSubKey);
          continue;
        }

        if (LOGGER.isLoggable(Level.INFO)) {
          // Sub key is normal key -> fix
          LOGGER.log(Level.INFO, "Subkey " + Long.toHexString(secSubKey.getKeyID())
              + " does not have a subkey key packet. Converting it...");
        }
        keyPacket = new PublicSubkeyPacket( // NOPMD: AvoidInstantiatingObjectsInLoops
            pubSubKey.getAlgorithm(),
            pubSubKey.getCreationTime(),
            keyPacket.getKey());
        publicPk.set(pubSubKey, keyPacket);

        final PGPPrivateKey privateKey = secSubKey.extractPrivateKey(decryptor);

        final PGPSecretKey secretKey = new PGPSecretKey(  // NOPMD: AvoidInstantiatingObjectsInLoops
            privateKey,
            pubSubKey,
            calculator,
            false,
            encryptor);
        fixedSecretKeys.add(secretKey);
      }

      return new PGPSecretKeyRing(fixedSecretKeys);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new UnsupportedOperationException(
          "Cannot apply fix due to an error while using reflections.", e);
    }
  }


  /**
   * This method tests sure if sub keys do consist of sub key packets.
   *
   * Bouncycastle versions up to and including 1.60 created {@link PGPSecretKeyRing}s which sub keys
   * consisted of
   * normal public key packets, which would result in lost keys when converting PGPSecretKeyRings to
   * PGPPublicKeyRings.
   *
   * This method throws a {@link RuntimeException} of a {@link NoSuchFieldException} or {@link
   * IllegalAccessException}.
   *
   * @param secretKeys possibly faulty PGPSecretKeyRing. Will NOT be changed.
   *
   * @return set of all subkey packets that do NOT have PUBLIC_SUBKEY set
   *
   * @throws PGPException in case we cannot dismantle or reassemble the key.
   * @see <a href="https://github.com/bcgit/bc-java/issues/381">Bouncycastle Java bug report #381</a>
   */
  public static Set<PGPSecretKey> violatingSubkeyPackets(PGPSecretKeyRing secretKeys) {
    requireNonNull(secretKeys, "secretKeys cannot be null");

    final Set<PGPSecretKey> violatingPackets = new HashSet<>();

    final Iterator<PGPSecretKey> secretKeyIterator = secretKeys.iterator();
    try {

      while (secretKeyIterator.hasNext()) {
        final PGPSecretKey secSubKey = secretKeyIterator.next();

        if (secSubKey.isMasterKey()) {
          continue;
        }

        final PGPPublicKey pubSubKey = secSubKey.getPublicKey();

        // check for public key packet type

        final PublicKeyPacket keyPacket = extractPublicKeyPacket(pubSubKey);

        if (keyPacket instanceof PublicSubkeyPacket) {
          continue;
        }

        // Sub key is a normal key, not a  PublicSubkeyPacket
        violatingPackets.add(secSubKey);
      }

      return violatingPackets;
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw
          new UnsupportedOperationException(
              "Cannot apply fix due to an error while using reflections.",
              e);
    }
  }

  private static PublicKeyPacket extractPublicKeyPacket(final PGPPublicKey pubSubKey)
      throws NoSuchFieldException, IllegalAccessException {
    final Field publicPk = pubSubKey.getClass().getDeclaredField("publicPk");
    publicPk.setAccessible(true);
    return (PublicKeyPacket) publicPk.get(pubSubKey);
  }
}
