package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import java.util.Map;

/**
 * Factory for convenience implementations of KeyringConfigCallback. . {@link
 * KeyringConfigCallback}
 */
public final class KeyringConfigCallbacks {

  // no construction
  private KeyringConfigCallbacks() {
  }

  @SuppressWarnings("PMD.UseVarargs")
  public static KeyringConfigCallback withPassword(char[] passphrase) {
    return new StaticPasswordKeyringConfigCallback(passphrase);
  }

  public static KeyringConfigCallback withPassword(String passphrase) {
    if (passphrase == null) {
      throw new IllegalArgumentException("passphrase must not be null");
    }
    return withPassword(passphrase.toCharArray());
  }

  public static KeyringConfigCallback withUnprotectedKeys() {
    return new UnprotectedKeysKeyringConfigCallback();
  }

  public static KeyringConfigCallback withPasswordsFromMap(
      Map<Long, char[]> mapSourceKeyIdToPassphrase) {
    if (mapSourceKeyIdToPassphrase == null) {
      throw new IllegalArgumentException("mapSourceKeyIdToPassphrase must not be null");
    }

    return new StaticPasswordFromMapKeyringConfigCallback(mapSourceKeyIdToPassphrase);
  }
}
