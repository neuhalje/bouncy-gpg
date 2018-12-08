package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import static java.util.Objects.requireNonNull;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;

/**
 * Implements a keyring based on resources. . Use-case: Baked in GPG keyring (probably only with
 * public keys) without distributing separate keyring files. . See the unit tests for an example:
 * (in tests)  name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs
 */
final class ResourceBasedKeyringConfig extends AbstractDefaultKeyringConfig {


  private final ClassLoader classLoader;
  private final String publicKeyringPath;
  private final String secretKeyringPath;

  /**
   * @param callback Callback to resolve secret key passwords
   * @param classLoader The classloader used to open the resources
   * @param publicKeyringPath path passed to classLoader.getResourceAsStream
   * @param secretKeyringPath path passed to classLoader.getResourceAsStream
   */
  public ResourceBasedKeyringConfig(@Nonnull KeyringConfigCallback callback,
      @Nonnull ClassLoader classLoader,
      @Nonnull String publicKeyringPath,
      @Nonnull String secretKeyringPath) {
    super(callback);
    requireNonNull(classLoader, "classLoader must not be null");
    requireNonNull(publicKeyringPath, "publicKeyringPath must not be null");
    requireNonNull(secretKeyringPath, "secretKeyringPath must not be null");

    this.classLoader = classLoader;
    this.publicKeyringPath = publicKeyringPath;
    this.secretKeyringPath = secretKeyringPath;
  }

  @Override
  protected InputStream getPublicKeyRingStream() throws IOException {
    return classLoader.getResourceAsStream(publicKeyringPath);
  }

  @Override
  protected InputStream getSecretKeyRingStream() throws FileNotFoundException {
    return classLoader.getResourceAsStream(secretKeyringPath);
  }
}
