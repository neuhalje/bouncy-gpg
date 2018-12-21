package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class PGPCompressionAlgorithmsTest {

  @Test
  public void recommendedAlgorithms_returnsPopulatesSet() {
    assertThat(PGPCompressionAlgorithms.recommendedAlgorithms(), is(not(empty())));
  }

  /*
   * Adapt test when enum is changed
   */
  @Test
  public void recommendedAlgorithms_returnsCorrectSet() {
    assertThat(PGPCompressionAlgorithms.recommendedAlgorithms(), containsInAnyOrder(
        PGPCompressionAlgorithms.BZIP2,
        PGPCompressionAlgorithms.ZIP,
        PGPCompressionAlgorithms.ZLIB,
        PGPCompressionAlgorithms.UNCOMPRESSED
    ));
  }

  @Test
  public void recommendedAlgorithmIds_returnsPopulatesArray() {
    assertThat(PGPCompressionAlgorithms.recommendedAlgorithmIds().length, greaterThan(0));
  }
}