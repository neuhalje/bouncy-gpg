package name.neuhalfen.projects.crypto.bouncycastle.openpgp.example;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildDecryptionInputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption.FSZipEntityStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption.ReencryptExplodedZipMultithreaded;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption.ZipEntityStrategy;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;

/**
 * Multithreaded implementation. Not tested that much.
 */
public class MainExplodedMultithreaded {
    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    public static void main(String[] args) {
        if (args.length != 6) {
            System.err.format("Usage %s  recipient pubKeyRing secKeyRing secKeyRingPassword sourceFile.zip.gpg destPath\n", "java -jar xxx.jar");
            System.exit(-1);
        } else {
            final String recipient = args[0];
            final File pubKeyRing = new File(args[1]);
            final File secKeyRing = new File(args[2]);
            final String secKeyRingPassword = args[3];
            final File sourceFile = new File(args[4]);
            final File destRootDir = new File(args[5]);

            try {
                installBCProvider();

                final KeyringConfig keyringConfig = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                        secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));


                long startTime = System.currentTimeMillis();

                final ZipEntityStrategy zipEntityStrategy = new FSZipEntityStrategy(destRootDir);
                final ReencryptExplodedZipMultithreaded reencryptExplodedZip = new ReencryptExplodedZipMultithreaded();

                final BuildEncryptionOutputStreamAPI.Build encryptionFactory = BouncyGPG
                        .encryptToStream()
                        .withConfig(keyringConfig)
                        .withStrongAlgorithms()
                        .toRecipient(recipient)
                        .andDoNotSign()
                        .binaryOutput();

                final BuildDecryptionInputStreamAPI.Build decryptionFactory = BouncyGPG.decryptAndVerifyStream()
                        .withConfig(keyringConfig)
                        .andValidateSomeoneSigned();

                try (
                        final InputStream encryptedSourceZIP = new FileInputStream(sourceFile);
                        final InputStream decryptedSourceZIP = decryptionFactory.fromEncryptedInputStream(encryptedSourceZIP)
                ) {
                    reencryptExplodedZip.explodeAndReencrypt(decryptedSourceZIP, zipEntityStrategy, encryptionFactory);
                }
                long endTime = System.currentTimeMillis();

                System.out.format("Re-Encryption took %.2f s\n", ((double) endTime - startTime) / 1000);
            } catch (Exception e) {
                System.err.format("ERROR: %s", e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
