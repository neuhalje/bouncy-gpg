package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.ReencryptExplodedZipSinglethread;
import org.junit.Test;

import java.io.File;
import java.io.InputStream;

import static org.junit.Assume.assumeNotNull;


public class ReencryptExplodedZipSinglethreadTest {

    protected name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.ReencryptExplodedZipSinglethread sut() {
        return new name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption.ReencryptExplodedZipSinglethread();
    }

    @Test
    public void reencrypting_smallZip_doesNotCrash() throws Exception {
        final InputStream exampleEncryptedZip = getClass().getClassLoader().getResourceAsStream("testdata/zip_encrypted_binary_signed.zip.gpg");
        assumeNotNull(exampleEncryptedZip);

        final EncryptionConfig encryptionConfig = Configs.buildConfigForEncryptionFromResources();
        final DecryptionConfig decryptionConfig = Configs.buildConfigForDecryptionFromResources();

        assumeNotNull(encryptionConfig);
        assumeNotNull(decryptionConfig);

        EncryptWithOpenPGP encryptWithOpenPGP = new EncryptWithOpenPGP(encryptionConfig);

        sut().explodeAndReencrypt(exampleEncryptedZip, decryptionConfig, encryptWithOpenPGP, new File(("/tmp/xxx")));
    }
}
