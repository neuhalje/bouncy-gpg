package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.Security;
import java.time.Instant;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.junit.Before;
import org.junit.Test;

public class BuildEncryptionOutputStreamAPITest {

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  @Test(expected = NullPointerException.class)
  public void encryptConfigure_NoConfigPassed_throws() throws Exception {
    BouncyGPG.encryptToStream().withConfig(null);
  }


  @Test
  public void encryptConfigure_ConfigPassed_notNull() throws Exception {
    assertNotNull(BouncyGPG.encryptToStream().withConfig(mockKeyringConfig()));
  }

  @Test
  public void encryptConfigureValidate_notNull() throws Exception {
    final BuildEncryptionOutputStreamAPI.WithAlgorithmSuite withConfig = BouncyGPG.encryptToStream()
        .withConfig(mockKeyringConfig());
    assumeNotNull(withConfig);

    assertNotNull(withConfig.withDefaultAlgorithms());
    assertNotNull(withConfig.withAlgorithms(DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG()));
  }

  @Test(expected = NullPointerException.class)
  public void encryptConfigureValidate_passNullRecipient_throws() throws Exception {
    final BuildEncryptionOutputStreamAPI.WithAlgorithmSuite.To to = BouncyGPG.encryptToStream()
        .withConfig(mockKeyringConfig()).withDefaultAlgorithms();
    assumeNotNull(to);

    to.toRecipient(null);
  }

  @Test(expected = PGPException.class)
  public void encryptConfigureValidate_passNotExistingRecipient_throws() throws Exception {

    final BuildEncryptionOutputStreamAPI.WithAlgorithmSuite.To to = BouncyGPG.encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender()).withDefaultAlgorithms();
    assumeNotNull(to);

    to.toRecipient("not existing");
  }


  @Test(expected = NullPointerException.class)
  public void withKeySelectionStrategy_NoStrategyPassed_throws() throws Exception {
    BouncyGPG.encryptToStream().withConfig(mockKeyringConfig()).withKeySelectionStrategy(null);
  }


  @Test(expected = IllegalStateException.class)
  public void withKeySelectionStrategy_isExclusiveWithSelectUidByAnyUidPart() throws Exception {
    BouncyGPG.encryptToStream().withConfig(mockKeyringConfig()).selectUidByAnyUidPart()
        .withKeySelectionStrategy(mockKeySelectionStrategy());
  }


  @Test()
  public void keySelectionStrategy_SelectUidByAnyUidPart_compatible_with_setReferenceDateForKeyValidityTo()
      throws Exception {
    BouncyGPG.encryptToStream().withConfig(mockKeyringConfig()).selectUidByAnyUidPart()
        .setReferenceDateForKeyValidityTo(Instant.MAX).withDefaultAlgorithms();
  }

  private KeySelectionStrategy mockKeySelectionStrategy() {
    return mock(KeySelectionStrategy.class);
  }

  private KeyringConfig mockKeyringConfig() throws IOException, PGPException {
    final KeyringConfig mockKeyringConfig = mock(KeyringConfig.class);
    when(mockKeyringConfig.getKeyFingerPrintCalculator())
        .thenReturn(mock(KeyFingerPrintCalculator.class));
    when(mockKeyringConfig.getPublicKeyRings()).thenReturn(mock(PGPPublicKeyRingCollection.class));
    when(mockKeyringConfig.getSecretKeyRings()).thenReturn(mock(PGPSecretKeyRingCollection.class));

    return mockKeyringConfig;
  }

}