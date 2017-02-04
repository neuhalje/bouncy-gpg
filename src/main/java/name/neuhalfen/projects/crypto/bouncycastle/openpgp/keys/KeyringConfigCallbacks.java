package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;


/**
 * Factory for convenience implementations of KeyringConfigCallback.
 *
 * {@link KeyringConfigCallback}
 */
public class KeyringConfigCallbacks {
    public static KeyringConfigCallback withPassword(char[] passphrase) {
        return new StaticPasswordKeyringConfigCallback(passphrase);
    }

    public static KeyringConfigCallback withPassword(String passphrase) {
        return withPassword(passphrase.toCharArray());
    }

    public static KeyringConfigCallback withUnprotectedKeys() {
        return new UnprotectedKeysKeyringConfigCallback();
    }
}
