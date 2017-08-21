package name.neuhalfen.projects.crypto.bouncycastle.openpgp;


@SuppressWarnings({"PMD.AtLeastOneConstructor","PMD.AccessorMethodGeneration","PMD.LawOfDemeter"})
public final class BouncyGPG {

  private BouncyGPG() {
  }

  /**
   * Entry point for stream based decryption.  Ultimately an encryption output stream is placed
   * before a user supplied output stream so that plaintext written to the encryption stream is
   * encrypted and written to the user supplied output stream. . Example:
   * https://github.com/neuhalje/bouncy-gpg/tree/master/examples/decrypt . Usage: . final
   * OutputStream encryptionStream = BouncyGPG .encryptToStream() .withConfig(Configs.keyringConfigFromFilesForSender())
   * .withDefaultAlgorithms() .toRecipient("recipient@example.com") .andSignWith("sender@example.com")
   * .armorAsciiOutput() .andWriteTo(cipherText); <p> encryptionStream.write(expectedPlaintext);
   * encryptionStream.close(); cipherText.close(); .
   *
   * @return The next build step. In the end the encryption stream.
   */
  public static BuildDecryptionInputStreamAPI decryptAndVerifyStream() {
    return new BuildDecryptionInputStreamAPI();
  }

  /**
   * Entry point for stream based encryption.  Ultimately a decrypting input stream is placed before
   * a user supplied stream with encrypted data. . Example: https://github.com/neuhalje/bouncy-gpg/tree/master/examples/encrypt
   * .
   *
   * @return The next build step. In the end the decryption stream.
   */
  public static BuildEncryptionOutputStreamAPI encryptToStream() {
    return new BuildEncryptionOutputStreamAPI();
  }

}
