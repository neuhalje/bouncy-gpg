package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;
import org.junit.Ignore;
import org.junit.Test;


/**
 * HashingOutputStream is a utility class used solely for testing. <p> This is 'meta test' ...
 *
 * @see HashingOutputStream
 */
public class HashingOutputStreamTest {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(HashingOutputStreamTest.class);

  @Test
  public void callingToString_onOpenStream_returnsEmptyString() throws NoSuchAlgorithmException {
    HashingOutputStream sut = HashingOutputStream.sha256();

    assertThat(sut.toString(), is(equalTo("")));
  }


  @Test
  public void callingToString_onEmptyStream_returnsCorrectHash()
      throws NoSuchAlgorithmException, IOException {
    HashingOutputStream sut = HashingOutputStream.sha256();
    sut.close();
    assertThat(sut.toString(),
        is(equalTo("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")));
  }

  @Test
  public void writingMinusOne_sameAsWriting0xff_returnsCorrectHash()
      throws NoSuchAlgorithmException, IOException {
    HashingOutputStream sut = HashingOutputStream.sha256();
    sut.write(-1);
    sut.close();

    HashingOutputStream sut2 = HashingOutputStream.sha256();
    sut2.write(0xff);
    sut2.close();
    assertThat(sut.toString(), is(equalTo(sut2.toString())));
  }


  @Test
  public void callingToString_onFullStream_returnsCorrectHash()
      throws NoSuchAlgorithmException, IOException {
    HashingOutputStream sut = HashingOutputStream.sha256();
    sut.write(
        "Those people who think they know everything are a great annoyance to those of us who do. Isaac Asimov"
            .getBytes(StandardCharsets.UTF_8));
    sut.close();
    assertThat(sut.toString(),
        is(equalTo("B06EE8C91425C5298AAC4B36897FE7260AC0581C5F407AA4BF52BC028391B169")));
  }


  @Test
  public void callingToString_onStreamWrittenByteByByte_returnsCorrectHash()
      throws NoSuchAlgorithmException, IOException {
    HashingOutputStream sut = HashingOutputStream.sha256();
    byte[] bytes = "Those people who think they know everything are a great annoyance to those of us who do. Isaac Asimov"
        .getBytes(StandardCharsets.UTF_8);

    for (byte b : bytes) {
      sut.write(b);
    }

    sut.close();
    assertThat(sut.toString(),
        is(equalTo("B06EE8C91425C5298AAC4B36897FE7260AC0581C5F407AA4BF52BC028391B169")));
  }

  @Test
  public void callingToString_onFullStream_returnsCorrectHash2()
      throws NoSuchAlgorithmException, IOException {
    HashingOutputStream sut = HashingOutputStream.sha256();
    sut.write("I love deadlines. I like the whooshing sound they make as they fly by. Douglas Adams"
        .getBytes(StandardCharsets.UTF_8));
    sut.close();
    assertThat(sut.toString(),
        is(equalTo("5A341E2D70CB67831E837AC0474E140627913C17113163E47F1207EA5C72F86F")));
  }

  @Test
  public void doubleClose_doesNotChangeStream_returnsCorrectHash()
      throws NoSuchAlgorithmException, IOException {
    HashingOutputStream sut = HashingOutputStream.sha256();
    sut.write(
        "Those people who think they know everything are a great annoyance to those of us who do. Isaac Asimov"
            .getBytes(StandardCharsets.UTF_8));
    sut.close();
    sut.close();
    assertThat(sut.toString(),
        is(equalTo("B06EE8C91425C5298AAC4B36897FE7260AC0581C5F407AA4BF52BC028391B169")));
  }
  //


  /**
   * This test is just a micro benchmark.
   */
  @Test
  @Ignore("this test is not a test of functionality")
  public void measureMaxPerformance()
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
    final int KB = 1024;
    final int MB = 1024 * KB;

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    final long sampleSizeMB = 1024;
    RandomDataInputStream in = new RandomDataInputStream(sampleSizeMB * MB);

    HashingOutputStream out = HashingOutputStream.sha512_Oracle();

    long start = System.currentTimeMillis();

    Streams.pipeAll(in, out);

    long end = System.currentTimeMillis();

    double MBBperMilliSecond = ((double) sampleSizeMB) / (end - start);
    double MBperSecond = MBBperMilliSecond * 1000;
    String msg = String.format("HashingOutputStream: delivers ~%f.2 MB/s", MBperSecond);
    LOGGER.warn(msg);

    assertThat("We need ultra fast hashing: more than 100 MB/s", MBperSecond,
        greaterThan(100.0));

  }
}