package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptionConfig;

import java.io.OutputStream;


/**
 * encrypt().withConfig().to(recipient).andSignWith().asOutputStream()
 */
public class BuildEncryptionOutputStreamAPI {
    private OutputStream sinkForEncryptedData;


    private EncryptionConfig encryptionConfig;
    private String signWith;
    private static String recipient;

    // Signature


    BuildEncryptionOutputStreamAPI() {
    }

    ;

    public To withConfig(EncryptionConfig encryptionConfig) {
        BuildEncryptionOutputStreamAPI.this.encryptionConfig = encryptionConfig;
        return new To();
    }


    public class To {
        public SignWith toRecipient(String recipient) {

            BuildEncryptionOutputStreamAPI.recipient = recipient;
            return new SignWith();
        }
    }

    public class SignWith {
        public Build andSignWith(String userId) {
            BuildEncryptionOutputStreamAPI.this.signWith = userId;
            return new Build();
        }

        public Build andDoNotSign() {
            BuildEncryptionOutputStreamAPI.this.signWith = null;
            return new Build();
        }
    }

    public class Build {

        public OutputStream asOutputStream(OutputStream sinkForEncryptedData) {
            // TODO Implement
            BuildEncryptionOutputStreamAPI.this.sinkForEncryptedData = sinkForEncryptedData;
            throw new AssertionError();
        }
    }
}
