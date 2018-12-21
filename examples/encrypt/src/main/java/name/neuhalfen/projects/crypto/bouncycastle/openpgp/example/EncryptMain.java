package name.neuhalfen.projects.crypto.bouncycastle.openpgp.example;


import java.io.BufferedOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;

public class EncryptMain {
  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(EncryptMain.class);



  public static void main(String[] args) {
    if (args.length != 7) {
      System.err.format(
          "Usage %s  sender recipient pubKeyRing secKeyRing secKeyRingPassword sourceFile destFile\n",
          "java -jar xxx.jar");
      System.exit(-1);
    } else {
      final String sender = args[0];
      final String recipient = args[1];
      final File pubKeyRing = new File(args[2]);
      final File secKeyRing = new File(args[3]);
      final String secKeyRingPassword = args[4];
      final Path sourceFile = Paths.get(args[5]);
      final Path destFile = Paths.get(args[6]);
      try {
        BouncyGPG.registerProvider();
        long startTime = System.currentTimeMillis();

        final int BUFFSIZE = 8 * 1024;
        LOGGER.trace("Using a write buffer of {} bytes\n", BUFFSIZE);

        final KeyringConfig keyringConfig = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
            secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));

        try (
            final OutputStream fileOutput = Files.newOutputStream(destFile);
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);

            final OutputStream outputStream = BouncyGPG
                .encryptToStream()
                .withConfig(keyringConfig)
                .withStrongAlgorithms()
                .toRecipient(recipient)
                .andSignWith(sender)
                .binaryOutput()
                .andWriteTo(bufferedOut);

            final InputStream is = Files.newInputStream(sourceFile)
        ) {
          Streams.pipeAll(is, outputStream);
        }
        long endTime = System.currentTimeMillis();

        LOGGER.info(String.format("Encryption took %.2f s",  ((double) endTime - startTime) / 1000));
      } catch (Exception e) {
        LOGGER.error("ERROR", e);
      }
    }
  }
}
