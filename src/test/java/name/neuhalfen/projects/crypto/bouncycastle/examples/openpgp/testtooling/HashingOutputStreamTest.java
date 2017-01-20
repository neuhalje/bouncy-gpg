package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling;

import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;


/**
 * HashingOutputStream is a utility class used solely for testing.
 *
 * @see HashingOutputStream
 */
public class HashingOutputStreamTest {

    @Test
    public void callingToString_onOpenStream_returnsEmptyString() throws NoSuchAlgorithmException {
        HashingOutputStream sut = HashingOutputStream.sha256();

        assertThat(sut.toString(), is(equalTo("")));
    }


    @Test
    public void callingToString_onEmptyStream_returnsCorrectHash() throws NoSuchAlgorithmException, IOException {
        HashingOutputStream sut = HashingOutputStream.sha256();
        sut.close();
        assertThat(sut.toString(), is(equalTo("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")));
    }

    @Test
    public void writingMinusOne_sameAsWriting0xff_returnsCorrectHash() throws NoSuchAlgorithmException, IOException {
        HashingOutputStream sut = HashingOutputStream.sha256();
        sut.write(-1);
        sut.close();

        HashingOutputStream sut2 = HashingOutputStream.sha256();
        sut2.write(0xff);
        sut2.close();
        assertThat(sut.toString(), is(equalTo(sut2.toString())));
    }


    @Test
    public void callingToString_onFullStream_returnsCorrectHash() throws NoSuchAlgorithmException, IOException {
        HashingOutputStream sut = HashingOutputStream.sha256();
        sut.write("Those people who think they know everything are a great annoyance to those of us who do. Isaac Asimov".getBytes("UTF-8"));
        sut.close();
        assertThat(sut.toString(), is(equalTo("B06EE8C91425C5298AAC4B36897FE7260AC0581C5F407AA4BF52BC028391B169")));
    }


    @Test
    public void callingToString_onStreamWrittenByteByByte_returnsCorrectHash() throws NoSuchAlgorithmException, IOException {
        HashingOutputStream sut = HashingOutputStream.sha256();
        byte[] bytes = "Those people who think they know everything are a great annoyance to those of us who do. Isaac Asimov".getBytes("UTF-8");

        for (byte b : bytes) {
            sut.write(b);
        }

        sut.close();
        assertThat(sut.toString(), is(equalTo("B06EE8C91425C5298AAC4B36897FE7260AC0581C5F407AA4BF52BC028391B169")));
    }

    @Test
    public void callingToString_onFullStream_returnsCorrectHash2() throws NoSuchAlgorithmException, IOException {
        HashingOutputStream sut = HashingOutputStream.sha256();
        sut.write("I love deadlines. I like the whooshing sound they make as they fly by. Douglas Adams".getBytes("UTF-8"));
        sut.close();
        assertThat(sut.toString(), is(equalTo("5A341E2D70CB67831E837AC0474E140627913C17113163E47F1207EA5C72F86F")));
    }

    @Test
    public void doubleClose_doesNotChangeStream_returnsCorrectHash() throws NoSuchAlgorithmException, IOException {
        HashingOutputStream sut = HashingOutputStream.sha256();
        sut.write("Those people who think they know everything are a great annoyance to those of us who do. Isaac Asimov".getBytes("UTF-8"));
        sut.close();
        sut.close();
        assertThat(sut.toString(), is(equalTo("B06EE8C91425C5298AAC4B36897FE7260AC0581C5F407AA4BF52BC028391B169")));
    }
    //
}