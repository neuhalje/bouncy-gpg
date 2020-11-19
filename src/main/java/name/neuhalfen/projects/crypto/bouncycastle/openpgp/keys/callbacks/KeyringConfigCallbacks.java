package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static java.util.Objects.requireNonNull;

import java.util.Map;

/**
 * Factory for convenience implementations of KeyringConfigCallback.
 * {@link KeyringConfigCallback}
 */
@SuppressWarnings({"PMD.ClassNamingConventions"})
public final class KeyringConfigCallbacks {

  // no construction
  private KeyringConfigCallbacks() {
  }

  /**
   * Use the passed passphrase to decrypt every key encountered.
   * @param passphrase passphrase to use
   * @return a prebuild instance
   */
  @SuppressWarnings("PMD.UseVarargs")
  public static KeyringConfigCallback withPassword(char[] passphrase) {
    return new StaticPasswordKeyringConfigCallback(passphrase);
  }
  /**
   * Use the passed passphrase to decrypt every key encountered.
   * @param passphrase passphrase to use
   * @return a prebuild instance
   */
  public static KeyringConfigCallback withPassword(String passphrase) {
    requireNonNull(passphrase, "passphrase must not be null");

    return withPassword(passphrase.toCharArray());
  }

  /**
   * Assume that all keys are unprotected.
   *
   * @return a prebuild instance
   */
  public static KeyringConfigCallback withUnprotectedKeys() {
    return new UnprotectedKeysKeyringConfigCallback();
  }

  /**
   * Use the passed map that contains the passphrase per keyID.
   *
   * @return a prebuild instance
   */
  public static KeyringConfigCallback withPasswordsFromMap(
      Map<Long, char[]> mapSourceKeyIdToPassphrase) {
    requireNonNull(mapSourceKeyIdToPassphrase, "mapSourceKeyIdToPassphrase must not be null");

    return new StaticPasswordFromMapKeyringConfigCallback(mapSourceKeyIdToPassphrase);
  }
}
