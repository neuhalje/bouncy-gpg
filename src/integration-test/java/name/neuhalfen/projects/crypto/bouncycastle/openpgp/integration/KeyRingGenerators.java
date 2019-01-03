package name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration;

import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyFlag;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyRingBuilder.WithPassphrase;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.Passphrase;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDHKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve.EllipticCurve;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.VersionCommand.VersionCommandResult;
import org.bouncycastle.openpgp.PGPException;

public final class KeyRingGenerators {

  @FunctionalInterface
  interface KeyRingGenerator {

    KeyringConfig generateKeyringWithBouncyGPG(VersionCommandResult gpgVersion,
        @Nullable String passphrase)
        throws IOException, PGPException, NoSuchAlgorithmException,
        NoSuchProviderException, InvalidAlgorithmParameterException;
  }

  private KeyRingGenerators() {/* utils */}


  final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
  final static String EMAIL_JULIET = "juliet@example.com";


  static KeyringConfig generateSimpleRSAKeyring(VersionCommandResult gpgVersion, String passphrase)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    assumeTrue("No passphrase supported for simple keyrings", passphrase == null);
    return BouncyGPG.createSimpleKeyring().simpleRsaKeyRing(UID_JULIET, RsaLength.RSA_3072_BIT);
  }


  static KeyringConfig generateComplexRSAKeyring(VersionCommandResult gpgVersion, String passphrase)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    final WithPassphrase builder = BouncyGPG.createKeyring().withSubKey(
        KeySpec.getBuilder(RSAKeyType.withLength(RsaLength.RSA_2048_BIT))
            .allowKeyToBeUsedTo(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
            .withDefaultAlgorithms())
        .withMasterKey(
            KeySpec.getBuilder(RSAKeyType.withLength(RsaLength.RSA_2048_BIT))
                .allowKeyToBeUsedTo(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER,
                    KeyFlag.SIGN_DATA)
                .withDefaultAlgorithms())
        .withPrimaryUserId(UID_JULIET);

    if (passphrase == null) {
      return builder.withoutPassphrase().build();
    } else {
      return builder.withPassphrase(Passphrase.fromString(passphrase)).build();
    }

  }

  static KeyringConfig generateSimpleECCKeyring(VersionCommandResult gpgVersion, String passphrase)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    assumeTrue("No passphrase supported for simple keyrings", passphrase == null);
    assumeTrue("Require at least GPG 2.1 for ECC", gpgVersion.isAtLeast(2, 1));

    return BouncyGPG.createSimpleKeyring().simpleEccKeyRing(UID_JULIET);
  }

  static KeyringConfig generateComplexEccAndRSAKeyring(VersionCommandResult gpgVersion,
      String passphrase)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    assumeTrue("Require at least GPG 2.1 for ECC", gpgVersion.isAtLeast(2, 1));

    final WithPassphrase builder = BouncyGPG.createKeyring().withSubKey(
        KeySpec.getBuilder(ECDHKeyType.fromCurve(EllipticCurve.CURVE_NIST_P521))
            .allowKeyToBeUsedTo(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
            .withDefaultAlgorithms())
        .withMasterKey(
            KeySpec.getBuilder(RSAKeyType.withLength(RsaLength.RSA_2048_BIT))
                .allowKeyToBeUsedTo(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER,
                    KeyFlag.SIGN_DATA)
                .withDefaultAlgorithms())
        .withPrimaryUserId(UID_JULIET);
    if (passphrase == null) {
      return builder.withoutPassphrase().build();
    } else {
      return builder.withPassphrase(Passphrase.fromString(passphrase)).build();
    }
  }

}
