package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class PGPSymmetricEncryptionAlgorithmsTest {

  @Test
  public void recommendedAlgorithms_returnsPopulatesSet() {
    assertThat(PGPSymmetricEncryptionAlgorithms.recommendedAlgorithms(), is(not(empty())));
  }

  /*
   * Adapt test when enum is changed
   */
  @Test
  public void recommendedAlgorithms_returnsCorrectSet() {
    assertThat(PGPSymmetricEncryptionAlgorithms.recommendedAlgorithms(), containsInAnyOrder(
        PGPSymmetricEncryptionAlgorithms.AES_256,
        PGPSymmetricEncryptionAlgorithms.AES_192,
        PGPSymmetricEncryptionAlgorithms.AES_128,
        PGPSymmetricEncryptionAlgorithms.CAMELLIA_256,
        PGPSymmetricEncryptionAlgorithms.CAMELLIA_192,
        PGPSymmetricEncryptionAlgorithms.CAMELLIA_128,
        PGPSymmetricEncryptionAlgorithms.TWOFISH,
        PGPSymmetricEncryptionAlgorithms.TRIPLE_DES
    ));
  }

  @Test
  public void recommendedAlgorithmIds_returnsPopulatesArray() {
    assertThat(PGPSymmetricEncryptionAlgorithms.recommendedAlgorithmIds().length, greaterThan(0));
  }
}