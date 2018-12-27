package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class PGPHashAlgorithmsTest {

  @Test
  public void recommendedAlgorithms_returnsPopulatesSet() {
    assertThat(PGPHashAlgorithms.recommendedAlgorithms(), is(not(empty())));
  }

  /*
   * Adapt test when enum is changed
   */
  @Test
  public void recommendedAlgorithms_returnsCorrectSet() {
    assertThat(PGPHashAlgorithms.recommendedAlgorithms(), containsInAnyOrder(
        PGPHashAlgorithms.SHA_512, PGPHashAlgorithms.SHA_384,
        PGPHashAlgorithms.SHA_256, PGPHashAlgorithms.SHA_224,
        PGPHashAlgorithms.RIPEMD160
    ));
  }

  @Test
  public void recommendedAlgorithmIds_returnsPopulatesArray() {
    assertThat(PGPHashAlgorithms.recommendedAlgorithmIds().length, greaterThan(0));
  }
}