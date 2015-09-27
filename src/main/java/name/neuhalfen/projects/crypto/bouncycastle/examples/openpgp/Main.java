package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;


import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.tls.HashAlgorithm;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Main {


    public static void main(String[] args) {
        if (args.length != 7) {
            System.err.format("Usage %s sender recipient pubKeyRing secKeyRing secKeyRingPassword sourceFile destFile\n", "java -jar xxx.jar");
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

                EncryptionConfig encryptionConfig = EncryptionConfig.withKeyRingsFromFiles(pubKeyRing, secKeyRing, sender, secKeyRingPassword, recipient, HashAlgorithm.sha1,
                        SymmetricKeyAlgorithmTags.AES_128);
                EncryptWithOpenPGP pgp = new EncryptWithOpenPGP(encryptionConfig);

                pgp.encryptAndSign(new FileInputStream(sourceFile), new FileOutputStream(destFile));
            } catch (Exception e) {
                System.err.format("ERROR: %s", e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
