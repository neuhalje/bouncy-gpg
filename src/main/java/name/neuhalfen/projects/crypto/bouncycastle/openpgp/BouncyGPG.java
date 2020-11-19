package name.neuhalfen.projects.crypto.bouncycastle.openpgp;


import java.security.Security;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyRingBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyRingBuilderImpl;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.SimpleKeyRingBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AccessorMethodGeneration", "PMD.LawOfDemeter",
    "PMD.ClassNamingConventions"})
public final class BouncyGPG {

  private BouncyGPG() {
  }

  /**
   * Entry point for stream based decryption.  Ultimately an encryption output stream is placed
   * before a user supplied output stream so that plaintext written to the encryption stream is
   * encrypted and written to the user supplied output stream. . Example:
   * https://github.com/neuhalje/bouncy-gpg/tree/master/examples/decrypt . Usage:
   * <pre>
   * final
   * OutputStream encryptionStream = BouncyGPG.encryptToStream()
   *    .withConfig(Configs.keyringConfigFromFilesForSender())
   *    .withDefaultAlgorithms()
   *    .toRecipient("recipient@example.com")
   *    .andSignWith("sender@example.com")
   *    .armorAsciiOutput()
   *    .andWriteTo(cipherText);
   *
   * encryptionStream.write(expectedPlaintext);
   * encryptionStream.close();
   * cipherText.close();
   * </pre>
   *
   * @return The next build step. In the end the encryption stream.
   */
  public static BuildDecryptionInputStreamAPI decryptAndVerifyStream() {
    return new BuildDecryptionInputStreamAPI();
  }

  /**
   * <p>Entry point for stream based encryption.  Ultimately a decrypting input stream is placed
   * before
   * a user supplied stream with encrypted data.
   * </p><p>
   * Example: https://github.com/neuhalje/bouncy-gpg/tree/master/examples/encrypt
   * </p>
   *
   * @return The next build step. In the end the decryption stream.
   */
  public static BuildEncryptionOutputStreamAPI encryptToStream() {
    return new BuildEncryptionOutputStreamAPI();
  }

  /**
   * Generate a new OpenPGP key ring.
   *
   * @return builder
   */
  public static KeyRingBuilder createKeyring() {
    return new KeyRingBuilderImpl();
  }

  /**
   * Generate a new OpenPGP key ring.
   *
   * @return builder
   */
  public static SimpleKeyRingBuilder createSimpleKeyring() {
    return new KeyRingBuilderImpl();
  }

  /**
   * <p>Register the BouncyCastle provider as first provider. If another instance of the
   * BouncyCastle provider is already registered it is removed.
   * </p>
   * <p>The BouncyCastle provider needs to be registered for BouncyGPG to work.</p>
   * <p>
   * This procedure also makes it possible to use BC on older Android devices that ship their own BC
   * implementation.
   * </p>
   */
  public static synchronized void registerProvider() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 0);
  }
}
