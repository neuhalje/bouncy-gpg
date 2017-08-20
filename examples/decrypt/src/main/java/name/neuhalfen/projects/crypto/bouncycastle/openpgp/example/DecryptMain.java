package name.neuhalfen.projects.crypto.bouncycastle.openpgp.example;


import java.io.BufferedOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;

public class DecryptMain {

  static void installBCProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public static void main(String[] args) {
    if (args.length != 5) {
      System.err.format("Usage %s pubKeyRing secKeyRing secKeyRingPassword sourceFile destFile\n",
          "java -jar xxx.jar");
      System.exit(-1);
    } else {

      final File pubKeyRing = new File(args[0]);
      final File secKeyRing = new File(args[1]);
      final String secKeyRingPassword = args[2];
      final Path sourceFile = Paths.get(args[3]);
      final Path destFile = Paths.get(args[4]);
      try {
        installBCProvider();
        long startTime = System.currentTimeMillis();

        final int BUFFSIZE = 8 * 1024;
        System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);

        final KeyringConfig keyringConfig = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
            secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));

        try (
            final InputStream cipherTextStream = Files.newInputStream(sourceFile);

            final OutputStream fileOutput = Files.newOutputStream(destFile);
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);

            final InputStream plaintextStream = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(keyringConfig)
                .andValidateSomeoneSigned()
                .fromEncryptedInputStream(cipherTextStream)

        ) {
          Streams.pipeAll(plaintextStream, bufferedOut);
        }
        long endTime = System.currentTimeMillis();

        System.out.format("Decryption took %.2f s\n", ((double) endTime - startTime) / 1000);
      } catch (Exception e) {
        System.err.format("ERROR: %s", e.getMessage());
        e.printStackTrace();
      }
    }
  }

}
