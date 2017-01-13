package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.ReencryptExplodedZipSinglethread;
import org.junit.Test;

import java.io.File;
import java.io.InputStream;

import static org.junit.Assume.assumeNotNull;


public class ExplodeAndReencryptTest {


    @Test
    public void reencrypting_smallZip_doesNotCrash() throws Exception {

        final EncryptionConfig encryptionConfig = Configs.buildConfigForEncryptionFromResources();
        final DecryptionConfig decryptionConfig = Configs.buildConfigForDecryptionFromResources();

        final InputStream exampleEncryptedZip = getClass().getClassLoader().getResourceAsStream("testdata/zip_encrypted_binary_signed.zip.gpg");


        assumeNotNull(encryptionConfig);
        assumeNotNull(decryptionConfig);
        assumeNotNull(exampleEncryptedZip);

        EncryptWithOpenPGP encryptWithOpenPGP = new EncryptWithOpenPGP(encryptionConfig);
        ReencryptExplodedZipSinglethread reencryptExplodedZip = new ReencryptExplodedZipSinglethread();

        reencryptExplodedZip.explodeAndReencrypt(exampleEncryptedZip, decryptionConfig, encryptWithOpenPGP, new File(("/tmp")));
    }


}
