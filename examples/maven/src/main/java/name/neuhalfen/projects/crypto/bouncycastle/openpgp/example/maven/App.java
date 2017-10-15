package name.neuhalfen.projects.crypto.bouncycastle.openpgp.example.maven;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

public class App {

  public final static String RECIPIENT_PUBLICE_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
      "Version: GnuPG v2\n" +
      "\n" +
      "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\n" +
      "57ubFTCKp1cP\n" +
      "=WsAP\n" +
      "-----END PGP PUBLIC KEY BLOCK-----";

  public final static String RECIPIENT_PRIVATE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
      "Version: GnuPG v2\n" +
      "\n" +
      "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\n" +
      "=t6Bs\n" +
      "-----END PGP PRIVATE KEY BLOCK-----";

  public final static String MESSAGE = "I'm a little teapot!";

  public static void main(String[] args)
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

    System.out.println("Initializing Bouncy Castle");

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    System.out.println("Creating keyring");

    final InMemoryKeyring keyring = KeyringConfigs
        .forGpgExportedKeys(KeyringConfigCallbacks.withPassword("recipient"));
    keyring.addSecretKey(RECIPIENT_PRIVATE_KEY.getBytes());
    keyring.addPublicKey(RECIPIENT_PUBLICE_KEY.getBytes());

    System.out.println("Encrypting ... ");

    ByteArrayOutputStream encrypted = new ByteArrayOutputStream();

    final OutputStream outputStream = BouncyGPG.encryptToStream()
        .withConfig(keyring)
        .withStrongAlgorithms()
        .toRecipient("recipient@example.com")
        .andSignWith("recipient@example.com")
        .armorAsciiOutput()
        .andWriteTo(encrypted);

    outputStream.write(MESSAGE.getBytes());
    outputStream.close();
    encrypted.close();

    final String cipherText = encrypted.toString();
    System.out.println("Encrypted:");
    System.out.println(cipherText);

    System.out.println("Decrypting ... ");
    ByteArrayInputStream cipherTextStream = new ByteArrayInputStream(cipherText.getBytes());

    final InputStream decryptedInputStream = BouncyGPG.decryptAndVerifyStream()
        .withConfig(keyring)
        .andRequireSignatureFromAllKeys("recipient@example.com")
        .fromEncryptedInputStream(cipherTextStream);

    byte[] plain = new byte[2048];
    int len = decryptedInputStream.read(plain);

    String plainText = new String(plain, 0, len);
    System.out.println(plainText);

  }
}
