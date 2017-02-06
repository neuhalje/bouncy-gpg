package name.neuhalfen.projects.crypto.bouncycastle.openpgp;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class BouncyGPG {
    // make sure the Bouncy Castle provider is available:
    // because of this we can avoid declaring throws NoSuchProviderException further down
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Entry point for stream based decryption.
     * .
     * Usage:
     * .
     * .
     * final InputStream plaintextStream = BouncyGPG.decryptAndVerifyStream()
     * .withConfig(Configs.buildConfigForDecryptionFromResources())
     * .andRequireSignatureFromAllKeys("sender@example.com")
     * .fromEncryptedInputStream(ciphertextStream);
     *
     * @return The next build step.
     */
    public static BuildDecryptionInputStreamAPI decryptAndVerifyStream() {
        return new BuildDecryptionInputStreamAPI();
    }

    public static BuildEncryptionOutputStreamAPI encryptToStream() {
        return new BuildEncryptionOutputStreamAPI();
    }

    public static BuildVerificationInputStreamAPI verifySignature() {
        return new BuildVerificationInputStreamAPI();
    }

}
