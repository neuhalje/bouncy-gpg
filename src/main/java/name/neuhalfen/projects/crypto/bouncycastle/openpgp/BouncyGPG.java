package name.neuhalfen.projects.crypto.bouncycastle.openpgp;


public final class BouncyGPG {

    /**
     * Entry point for stream based decryption.
     * .
     * Usage:
     * .
     * final OutputStream encryptionStream = BouncyGPG
     * .encryptToStream()
     * .withConfig(Configs.keyringConfigFromFilesForSender())
     * .withDefaultAlgorithms()
     * .toRecipient("recipient@example.com")
     * .andSignWith("sender@example.com")
     * .armorAsciiOutput()
     * .andWriteTo(cipherText);
     * <p>
     * encryptionStream.write(expectedPlaintext);
     * encryptionStream.close();
     * cipherText.close();
     * .
     *
     * @return The next build step.
     */
    public static BuildDecryptionInputStreamAPI decryptAndVerifyStream() {
        return new BuildDecryptionInputStreamAPI();
    }

    public static BuildEncryptionOutputStreamAPI encryptToStream() {
        return new BuildEncryptionOutputStreamAPI();
    }

}
