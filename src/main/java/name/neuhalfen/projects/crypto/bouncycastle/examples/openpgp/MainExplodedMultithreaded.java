package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.ReencryptExplodedZipMultithreaded;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.tls.HashAlgorithm;

import java.io.File;
import java.io.FileInputStream;

/**
 * Multithreaded implementation. Not tested that much.
 */
public class MainExplodedMultithreaded {


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

                EncryptWithOpenPGP encryptWithOpenPGP = new EncryptWithOpenPGP(encryptionConfig);
                DecryptWithOpenPGP decryptWithOpenPGP = new DecryptWithOpenPGP(decryptionConfig);
                ReencryptExplodedZipMultithreaded reencryptExplodedZip = new ReencryptExplodedZipMultithreaded();


                long startTime = System.currentTimeMillis();


                reencryptExplodedZip.explodeAndReencrypt(new FileInputStream(sourceFile), decryptWithOpenPGP, encryptWithOpenPGP, destRootDir);


                long endTime = System.currentTimeMillis();

                System.out.format("Re-Encryption took %.2f s\n", ((double) endTime - startTime) / 1000);
            } catch (Exception e) {
                System.err.format("ERROR: %s", e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
