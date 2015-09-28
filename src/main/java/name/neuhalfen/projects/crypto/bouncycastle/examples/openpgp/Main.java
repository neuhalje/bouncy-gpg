package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;


import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.tls.HashAlgorithm;

import java.io.*;

public class Main {


    public static void main(String[] args) {
        if (args.length != 8 ) {
            System.err.format("Usage %s [buffered|unbuffered] sender recipient pubKeyRing secKeyRing secKeyRingPassword sourceFile destFile\n", "java -jar xxx.jar");
            System.exit(-1);
        } else {
            final String bufferMode = args[0];
            final String sender = args[1];
            final String recipient = args[2];
            final File pubKeyRing = new File(args[3]);
            final File secKeyRing = new File(args[4]);
            final String secKeyRingPassword = args[5];
            final File sourceFile = new File(args[6]);
            final File destFile = new File(args[7]);
            try {

                EncryptionConfig encryptionConfig = EncryptionConfig.withKeyRingsFromFiles(pubKeyRing,
                        secKeyRing,
                        sender,
                        secKeyRingPassword,
                        recipient,
                        HashAlgorithm.sha1,
                        SymmetricKeyAlgorithmTags.AES_128);

                EncryptWithOpenPGP pgp = new EncryptWithOpenPGP(encryptionConfig);

                long startTime = System.currentTimeMillis();

                final boolean doBuffer = bufferMode.equals("buffered");
                final OutputStream outputStream ;

                if (doBuffer) {
                    final  int BUFFSIZE = 8*1024;
                    outputStream = new BufferedOutputStream(new FileOutputStream(destFile),BUFFSIZE);
                    System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);
                } else {
                    outputStream = new FileOutputStream(destFile);
                    System.out.format("-- Using NO write buffer\n");
                }

                pgp.encryptAndSign(new FileInputStream(sourceFile), outputStream);
                long endTime = System.currentTimeMillis();

                System.out.format("Encryption took %.2f s\n", ((double)endTime-startTime)/1000);
            } catch (Exception e) {
                System.err.format("ERROR: %s", e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
