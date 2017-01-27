package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;

import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;


/**
 * "Meta test".
 */
public class RandomDataInputStreamTest {
    private final int KB = 1024;
    private final int MB = 1024 * KB;
    private final int GB = 1024 * MB;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(RandomDataInputStreamTest.class);

    /**
     * This test asserts that the fake data source for tests with large data sets is not the bottleneck.
     */
    @Test
    public void measureRandomDataInputStreamMaxPerformance() throws IOException {
        final int sampleSizeMB = 100;
        RandomDataInputStream sut = new RandomDataInputStream(sampleSizeMB * MB);

        long start = System.currentTimeMillis();
        while (sut.read() > 0) {
        }
        long end = System.currentTimeMillis();

        double MBBperMilliSecond = ((double) sampleSizeMB) / (end - start);
        double GBperSecond = MBBperMilliSecond * 1000 / 1024;
        String msg = String.format("RandomDataInputStream: delivers ~%f.2 GB/s", GBperSecond);
        LOGGER.warn(msg);

        assertThat("We need ultra fast fake source data: more than 50 GB/s", GBperSecond, greaterThan(50.0));

    }
}