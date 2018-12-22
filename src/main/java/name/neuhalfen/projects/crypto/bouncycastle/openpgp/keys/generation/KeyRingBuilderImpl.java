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


import static java.util.Objects.requireNonNull;
import static name.neuhalfen.projects.crypto.internal.Preconditions.checkArgument;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.internal.KeyRingSubKeyFixUtil;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDH;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDSA;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.KeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSA_GENERAL;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve.EllipticCurve;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class KeyRingBuilderImpl implements KeyRingBuilder {

  private final Charset UTF8 = Charset.forName("UTF-8");

  private List<KeySpec> keySpecs = new ArrayList<>();
  private String userId;
  private Passphrase passphrase;

  /**
   * Creates a simple RSA KeyPair of length {@code length} with user-id {@code userId}.
   * The KeyPair consists of a single RSA master key which is used for signing, encryption and
   * certification.
   *
   * @param userId user id.
   * @param length length in bits.
   *
   * @return {@link PGPSecretKeyRing} containing the KeyPair.
   */
  public KeyringConfig simpleRsaKeyRing(String userId, RsaLength length)
      throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
    requireNonNull(userId, "userId must not be null");
    requireNonNull(length, "length must not be null");

    return withMasterKey(
        KeySpec.getBuilder(RSA_GENERAL.withLength(length))
            .withDefaultKeyFlags()
            .withDefaultAlgorithms())
        .withPrimaryUserId(userId)
        .withoutPassphrase()
        .build();
  }

  /**
   * Creates a key ring consisting of an ECDSA master key and an ECDH sub-key.
   * The ECDSA master key is used for signing messages and certifying the sub key.
   * The ECDH sub-key is used for encryption of messages.
   *
   * @param userId user-id
   *
   * @return {@link PGPSecretKeyRing} containing the key pairs.
   */
  public KeyringConfig simpleEcKeyRing(String userId)
      throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
    requireNonNull(userId, "userId must not be null");

    return withSubKey(
        KeySpec.getBuilder(ECDH.fromCurve(EllipticCurve.CURVE_P256))
            .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
            .withDefaultAlgorithms())
        .withMasterKey(
            KeySpec.getBuilder(ECDSA.fromCurve(EllipticCurve.CURVE_P256))
                .withKeyFlags(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                .withDefaultAlgorithms())
        .withPrimaryUserId(userId)
        .withoutPassphrase()
        .build();
  }

  @Override
  public KeyRingBuilder withSubKey(KeySpec type) {
    requireNonNull(type, "type must not be null");

    KeyRingBuilderImpl.this.keySpecs.add(type);
    return this;
  }

  @Override
  public WithPrimaryUserId withMasterKey(KeySpec spec) {
    requireNonNull(spec, "spec must not be null");
    checkArgument((spec.getSubpackets().getKeyFlags() & KeyFlags.CERTIFY_OTHER) != 0,
        "Certification Key MUST have KeyFlag CERTIFY_OTHER)");

    KeyRingBuilderImpl.this.keySpecs.add(0, spec);
    return new WithPrimaryUserIdImpl();
  }

  class WithPrimaryUserIdImpl implements WithPrimaryUserId {

    @Override
    public WithPassphrase withPrimaryUserId(String userId) {
      requireNonNull(userId, "userId must not be null");

      KeyRingBuilderImpl.this.userId = userId;
      return new WithPassphraseImpl();
    }

    @Override
    public WithPassphrase withPrimaryUserId(byte[] userId) {
      requireNonNull(userId, "userId must not be null");
      checkArgument(userId.length > 0, "userId mus have length >0");

      return withPrimaryUserId(new String(userId, UTF8));
    }
  }

  class WithPassphraseImpl implements WithPassphrase {

    @Override
    public Build withPassphrase(Passphrase passphrase) {
      requireNonNull(passphrase, "passphrase must not be null");
      KeyRingBuilderImpl.this.passphrase = passphrase;
      return new BuildImpl();
    }

    @Override
    public Build withoutPassphrase() {
      KeyRingBuilderImpl.this.passphrase = null;
      return new BuildImpl();
    }

    class BuildImpl implements Build {

      @Override
      public KeyringConfig build()
          throws NoSuchAlgorithmException, PGPException, NoSuchProviderException,
          InvalidAlgorithmParameterException, IOException {

        // Hash Calculator
        PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build()
            .get(PGPHashAlgorithms.SHA1.getAlgorithmId());

        // Encryptor for encrypting secret keys
        PBESecretKeyEncryptor encryptor = passphrase == null ?
            null : // unencrypted key pair, otherwise AES-256 encrypted
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calculator)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(passphrase != null ? passphrase.getChars() : null);

        if (passphrase != null) {
          passphrase.clear();
        }

        // First key is the Master Key
        KeySpec certKeySpec = keySpecs.get(0);
        // Remove master key, so that we later only add sub keys.
        keySpecs.remove(0);

        // Generate Master Key
        PGPKeyPair certKey = generateKeyPair(certKeySpec);

        // Signer for creating self-signature
        PGPContentSignerBuilder signer = new JcaPGPContentSignerBuilder(
            certKey.getPublicKey().getAlgorithm(), PGPHashAlgorithms.SHA_512.getAlgorithmId())
            .setProvider(BouncyCastleProvider.PROVIDER_NAME);

        PGPSignatureSubpacketVector hashedSubPackets = certKeySpec.getSubpackets();

        // Generator which the user can get the key pair from
        PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, certKey,
            userId, calculator,
            hashedSubPackets, null, signer, encryptor);

        for (KeySpec subKeySpec : keySpecs) {
          PGPKeyPair subKey = generateKeyPair(subKeySpec);
          if (subKeySpec.isInheritedSubPackets()) {
            ringGenerator.addSubKey(subKey);
          } else {
            ringGenerator.addSubKey(subKey, subKeySpec.getSubpackets(), null);
          }
        }

        PGPPublicKeyRing publicKeys = ringGenerator.generatePublicKeyRing();
        PGPSecretKeyRing secretKeys = ringGenerator.generateSecretKeyRing();

        // TODO: Remove once BC 1.61 is released
        secretKeys = KeyRingSubKeyFixUtil.repairSubkeyPackets(secretKeys, null, null);

        final InMemoryKeyring keyring;
        if (passphrase == null) {
          keyring = KeyringConfigs
              .forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
        } else {
          keyring = KeyringConfigs
              .forGpgExportedKeys(KeyringConfigCallbacks.withPassword(passphrase.getChars()));

        }

        keyring.addSecretKeyRing(secretKeys);
        keyring.addPublicKeyRing(publicKeys);
        return keyring;
      }

      private PGPKeyPair generateKeyPair(KeySpec spec)
          throws NoSuchProviderException, NoSuchAlgorithmException, PGPException,
          InvalidAlgorithmParameterException {
        KeyType type = spec.getKeyType();
        KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance(
            type.getName(), BouncyCastleProvider.PROVIDER_NAME);
        certKeyGenerator.initialize(type.getAlgorithmSpec());

        // Create raw Key Pair
        KeyPair keyPair = certKeyGenerator.generateKeyPair();

        // Form PGP key pair
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(type.getAlgorithm().getAlgorithmId(),
            keyPair, new Date());

        return pgpKeyPair;
      }
    }
  }
}
