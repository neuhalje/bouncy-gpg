package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import static java.util.Objects.requireNonNull;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import org.bouncycastle.openpgp.PGPException;

/**
 * Factory for keyring configs.
 */
@SuppressWarnings({"PMD.ClassNamingConventions"})
public final class KeyringConfigs {

  // no instances
  private KeyringConfigs() {
  }

  /**
   * Create a config by reading keyrings from files.
   *
   * @param publicKeyring E.g. src/test/resources/sender.gpg.d/pubring.gpg
   * @param secretKeyring E.g. src/test/resources/sender.gpg.d/secring.gpg
   * @param callback see KeyringConfigCallbacks
   *
   * @return the config
   */
  public static KeyringConfig withKeyRingsFromFiles(final File publicKeyring,
      final File secretKeyring,
      KeyringConfigCallback callback) {

    requireNonNull(publicKeyring, "publicKeyring must not be null");
    requireNonNull(secretKeyring, "secretKeyring must not be null");
    requireNonNull(callback, "callback must not be null");

    return new FileBasedKeyringConfig(callback, publicKeyring, secretKeyring);
  }

  /**
   * Create a config by reading keyrings from streams. The streams will be closed.
   *
   * The stream can be null, resulting in an empty keyring.
   *
   * @param publicKeyring E.g. a FileInputStream to src/test/resources/sender.gpg.d/pubring.gpg.
   * @param secretKeyring E.g. src/test/resources/sender.gpg.d/secring.gpg
   * @param callback see KeyringConfigCallbacks
   *
   * @return the config
   *
   * @throws IOException the streams fail to deliver
   * @throws PGPException failed to read the keyrings
   */
  public static KeyringConfig withKeyRingsFromStreams(@Nullable final InputStream publicKeyring,
      @Nullable final InputStream secretKeyring,
      KeyringConfigCallback callback) throws IOException, PGPException {

    requireNonNull(callback, "callback must not be null");

    return StreamBasedKeyringConfig.build(callback, publicKeyring, secretKeyring);
  }

  /**
   * Create a config by reading keyrings from the classpath.
   *
   * @param classLoader E.g. DecryptWithOpenPGPTest.class.getClassLoader()
   * @param publicKeyringPath E.g. "recipient.gpg.d/pubring.gpg"
   * @param secretKeyringPath E.g. "recipient.gpg.d/secring.gpg"
   * @param callback see KeyringConfigCallbacks
   *
   * @return the config
   */
  public static KeyringConfig withKeyRingsFromResources(final ClassLoader classLoader,
      final String publicKeyringPath,
      final String secretKeyringPath,
      final KeyringConfigCallback callback) {

    requireNonNull(publicKeyringPath, "publicKeyringPath must not be null");
    requireNonNull(secretKeyringPath, "secretKeyringPath must not be null");
    requireNonNull(callback, "callback must not be null");

    return new ResourceBasedKeyringConfig(callback, classLoader, publicKeyringPath,
        secretKeyringPath);
  }

  /**
   * Create a config that can parse keys exported in gpg.
   *
   * @param callback see KeyringConfigCallbacks
   *
   * @return the config
   *
   * @throws IOException IO is dangerous
   * @throws PGPException Could not create keyrings
   */
  public static InMemoryKeyring forGpgExportedKeys(final KeyringConfigCallback callback)
      throws IOException, PGPException {
    requireNonNull(callback, "callback must not be null");

    return new InMemoryKeyring(callback);
  }
}
