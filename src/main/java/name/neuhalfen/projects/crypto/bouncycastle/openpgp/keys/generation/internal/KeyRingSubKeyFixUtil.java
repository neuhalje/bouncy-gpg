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
import java.util.Iterator;
import java.util.List;
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

public class KeyRingSubKeyFixUtil {

    private static final Logger LOGGER = Logger.getLogger(KeyRingSubKeyFixUtil.class.getName());

    private KeyRingSubKeyFixUtil(){/* Util Class */}
    /**
     * This method makes sure, that sub keys do consist of sub key packets.
     * Bouncycastle versions up to and including 1.60 created {@link PGPSecretKeyRing}s which sub keys consisted of
     * normal public key packets, which would result in lost keys when converting PGPSecretKeyRings to PGPPublicKeyRings.
     *
     * This method throws a {@link RuntimeException} of a {@link NoSuchFieldException} or {@link IllegalAccessException}.
     *
     * @see <a href="https://github.com/bcgit/bc-java/issues/381">Bouncycastle Java bug report #381</a>
     *
     * @param secretKeys possibly faulty PGPSecretKeyRing
     * @param decryptor decryptor in case the keys are encrypted (can be null)
     * @param encryptor encryptor to re-encrypt the keys in case they are encrypted (can be null)
     *
     * @return fixed PGPSecretKeyRing
     *
     * @throws PGPException in case we cannot dismantle or reassemble the key.
     */
    public static PGPSecretKeyRing repairSubkeyPackets(PGPSecretKeyRing secretKeys,
                                                       @Nullable PBESecretKeyDecryptor decryptor,
                                                       @Nullable PBESecretKeyEncryptor encryptor)
            throws PGPException {
        requireNonNull(secretKeys, "secretKeys cannot be null");

        PGPDigestCalculator calculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);

        List<PGPSecretKey> _secretKeys = new ArrayList<>();
        Iterator<PGPSecretKey> secretKeyIterator = secretKeys.iterator();
        try {

            while (secretKeyIterator.hasNext()) {
                PGPSecretKey secSubKey = secretKeyIterator.next();

                if (secSubKey.isMasterKey()) {
                    LOGGER.log(Level.INFO, Long.toHexString(secSubKey.getKeyID()) + " is master key. Skip.");
                    _secretKeys.add(secSubKey);
                    continue;
                }

                PGPPublicKey pubSubKey = secSubKey.getPublicKey();

                // check for public key packet type

                Field publicPk = pubSubKey.getClass().getDeclaredField("publicPk");
                publicPk.setAccessible(true);
                PublicKeyPacket keyPacket = (PublicKeyPacket) publicPk.get(pubSubKey);

                if (keyPacket instanceof PublicSubkeyPacket) {
                    // Sub key is already sub key
                    _secretKeys.add(secSubKey);
                    continue;
                }

                // Sub key is normal key -> fix
                LOGGER.log(Level.INFO, "Subkey " + Long.toHexString(secSubKey.getKeyID()) + " does not have a subkey key packet. Convert it...");
                keyPacket = new PublicSubkeyPacket(pubSubKey.getAlgorithm(), pubSubKey.getCreationTime(), keyPacket.getKey());
                publicPk.set(pubSubKey, keyPacket);

                PGPPrivateKey privateKey = secSubKey.extractPrivateKey(decryptor);

                PGPSecretKey secretKey = new PGPSecretKey(privateKey, pubSubKey, calculator, false, encryptor);
                _secretKeys.add(secretKey);
            }

            return new PGPSecretKeyRing(_secretKeys);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Cannot apply fix due to an error while using reflections.", e);
        }
    }
}
