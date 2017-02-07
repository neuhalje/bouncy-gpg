package name.neuhalfen.projects.crypto.bouncycastle.openpgp;


public class BouncyGPG {

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
