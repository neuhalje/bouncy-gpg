package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;


/**
 * FIXME: document
 */
public class KeyringConfigCallbacks {
    public static KeyringConfigCallback withPassword(char[] passphrase) {
        return new StaticPasswordKeyringConfigCallback(passphrase);
    }

    public static KeyringConfigCallback withPassword(String passphrase) {
        return new StaticPasswordKeyringConfigCallback(passphrase.toCharArray());
    }

    public static KeyringConfigCallback withUnprotectedKeys() {
        return new UnprotectedKeysKeyringConfigCallback();
    }
}
