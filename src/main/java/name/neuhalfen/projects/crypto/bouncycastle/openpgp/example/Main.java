package name.neuhalfen.projects.crypto.bouncycastle.openpgp.example;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.Security;

public class Main {
    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        if (args.length != 7) {
            System.err.format("Usage %s  sender recipient pubKeyRing secKeyRing secKeyRingPassword sourceFile destFile\n", "java -jar xxx.jar");
            System.exit(-1);
        } else {
            final String sender = args[0];
            final String recipient = args[1];
            final File pubKeyRing = new File(args[2]);
            final File secKeyRing = new File(args[3]);
            final String secKeyRingPassword = args[4];
            final File sourceFile = new File(args[5]);
            final File destFile = new File(args[6]);
            try {
                installBCProvider();
                long startTime = System.currentTimeMillis();

                final int BUFFSIZE = 8 * 1024;
                System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);

                final KeyringConfig keyringConfig = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                        secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));


                try (
                        final FileOutputStream fileOutput = new FileOutputStream(destFile);
                        final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);

                        final OutputStream outputStream = BouncyGPG
                                .encryptToStream()
                                .withConfig(keyringConfig)
                                .withStrongAlgorithms()
                                .toRecipient(recipient)
                                .andSignWith(sender)
                                .binaryOutput()
                                .andWriteTo(bufferedOut);

                        final FileInputStream is = new FileInputStream(sourceFile)
                ) {
                    Streams.pipeAll(is, outputStream);
                }
                long endTime = System.currentTimeMillis();

                System.out.format("Encryption took %.2f s\n", ((double) endTime - startTime) / 1000);
            } catch (Exception e) {
                System.err.format("ERROR: %s", e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
