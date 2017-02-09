package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import java.util.Map;

/**
 * Factory for convenience implementations of KeyringConfigCallback.
 * .
 * {@link KeyringConfigCallback}
 */
public class KeyringConfigCallbacks {
    public static KeyringConfigCallback withPassword(char[] passphrase) {
        return new StaticPasswordKeyringConfigCallback(passphrase);
    }

    public static KeyringConfigCallback withPassword(String passphrase) {
        if (passphrase == null) {
            throw new NullPointerException("passphrase must not be null");
        }
        return withPassword(passphrase.toCharArray());
    }

    public static KeyringConfigCallback withUnprotectedKeys() {
        return new UnprotectedKeysKeyringConfigCallback();
    }

    public static KeyringConfigCallback withPasswordsFromMap(Map<Long, char[]> copySourceKeyIdToPassphrase) {
        if (copySourceKeyIdToPassphrase == null) {
            throw new NullPointerException("copySourceKeyIdToPassphrase must not be null");
        }

        return new StaticPasswordFromMapKeyringConfigCallback(copySourceKeyIdToPassphrase);
    }
}
