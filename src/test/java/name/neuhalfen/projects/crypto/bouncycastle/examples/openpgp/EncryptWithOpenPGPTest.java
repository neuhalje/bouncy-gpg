package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.DevNullOutputStream;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.RandomDataInputStream;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;


public class EncryptWithOpenPGPTest {


    @Test
    public void encryptionAndSigning_smallAmountsOfData_doesNotCrash() throws IOException, SignatureException, NoSuchAlgorithmException {

        StreamEncryption sut = new EncryptWithOpenPGP(Configs.buildConfigForEncryptionFromResources());

        DevNullOutputStream out = new DevNullOutputStream();

        final int sampleSize = 1 * Configs.KB;
        sut.encryptAndSign(someRandomInputData(sampleSize), out);

        assertThat("A compression>50% is fishy!", out.getBytesWritten(), greaterThan(sampleSize / 2));
    }

    @Test
    public void encryptionAndSigning_10MB_isFast() throws IOException, SignatureException, NoSuchAlgorithmException {
        StreamEncryption sut = new EncryptWithOpenPGP(Configs.buildConfigForEncryptionFromResources());

        DevNullOutputStream out = new DevNullOutputStream();

        final int sampleSize = 10 * Configs.MB;
        sut.encryptAndSign(someRandomInputData(sampleSize), out);

        assertThat("A compression>50% is fishy!", out.getBytesWritten(), greaterThan(sampleSize / 2));
    }


    @Test
    @Ignore("this test is very slow (~2min)")
    public void encryptionAndSigning_1GB_doesNotCrash() throws IOException, SignatureException, NoSuchAlgorithmException {
        StreamEncryption sut = new EncryptWithOpenPGP(Configs.buildConfigForEncryptionFromResources());

        DevNullOutputStream out = new DevNullOutputStream();

        final int sampleSize = 1 * Configs.GB;
        sut.encryptAndSign(someRandomInputData(sampleSize), out);


        assertThat("A compression>50% is fishy!", out.getBytesWritten(), greaterThan(sampleSize / 2));
    }


    private InputStream someRandomInputData(int len) {
        return new RandomDataInputStream(len);
    }

}
