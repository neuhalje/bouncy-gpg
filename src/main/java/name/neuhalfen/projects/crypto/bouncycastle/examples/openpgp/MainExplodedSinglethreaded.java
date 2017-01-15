package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptWithOpenPGPInputStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.FSZipEntityStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.ReencryptExplodedZipSinglethread;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.ZipEntityStrategy;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.tls.HashAlgorithm;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class MainExplodedSinglethreaded {


    public static void main(String[] args) {
        if (args.length != 7) {
            System.err.format("Usage %s  sender recipient pubKeyRing secKeyRing secKeyRingPassword sourceFile.zip.gpg destPath\n", "java -jar xxx.jar");
            System.exit(-1);
        } else {
            final String sender = args[0];
            final String recipient = args[1];
            final File pubKeyRing = new File(args[2]);
            final File secKeyRing = new File(args[3]);
            final String secKeyRingPassword = args[4];
            final File sourceFile = new File(args[5]);
            final File destRootDir = new File(args[6]);

            try {

                // Encrypt to self
                EncryptionConfig encryptionConfig = EncryptionConfig.withKeyRingsFromFiles(pubKeyRing,
                        secKeyRing,
                        recipient,
                        secKeyRingPassword,
                        recipient,
                        HashAlgorithm.sha1,
                        SymmetricKeyAlgorithmTags.AES_128);

                DecryptionConfig decryptionConfig = DecryptionConfig.withKeyRingsFromFiles(pubKeyRing,
                        secKeyRing,
                        false, secKeyRingPassword);
                final DecryptWithOpenPGPInputStreamFactory decryptWithOpenPGPInputStreamFactory = new DecryptWithOpenPGPInputStreamFactory(decryptionConfig);

                long startTime = System.currentTimeMillis();

                final EncryptWithOpenPGP encryptWithOpenPGP = new EncryptWithOpenPGP(encryptionConfig);
                final ZipEntityStrategy zipEntityStrategy = new FSZipEntityStrategy(destRootDir);
                final ReencryptExplodedZipSinglethread reencryptExplodedZip = new ReencryptExplodedZipSinglethread();


                try (
                        final InputStream encryptedStream = new FileInputStream(sourceFile);
                        final InputStream decryptedStream = decryptWithOpenPGPInputStreamFactory.wrapWithDecryptAndVerify(encryptedStream);
                ) {
                    reencryptExplodedZip.explodeAndReencrypt(decryptedStream, zipEntityStrategy, encryptWithOpenPGP);
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
