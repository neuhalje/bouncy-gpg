package name.neuhalfen.projects.crypto.symmetric.keygeneration;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.Callable;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;


/**
 * Simple tests that mostly mirror the factory code and make sure the contract
 * is held.
 */
public class SymmetricMasterKeySetupTest {

    /*
    @Test
    public void buildingDefaultConfiguration_forPasswordBasedKeys_usesExpectedSettings() throws Exception {

        final DerivedKeyFactoryConfig keyFactoryConfig =
                SymmetricMasterKeySetup
                        .setupMasterKeyForDeterministicSymmetricKeyDerivation()
                        .forAES128()
                        .withKeyDerivationForMasterKeyBasedOnPasswords()
                        .withFastPerRecordDerivation()
                        .andUsingInsecureDefaultSalt()
                        .getDerivedKeyFactoryConfig();

        assertFor_AES128(keyFactoryConfig);
        assertFor_fastPerRecordDerivation(keyFactoryConfig);
        assertFor_PasswordBasedKeyDerivation(keyFactoryConfig);
        assertFor_aSaltValueIsSet(keyFactoryConfig);
        assertThat_theCorrectDefaultSaltValueIsSet(keyFactoryConfig);
    }

    @Test
    public void buildingDefaultConfiguration_forStrongCryptographic_usesExpectedSettings() throws Exception {

        final DerivedKeyFactoryConfig keyFactoryConfig = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial()
                .withFastPerRecordDerivation()
                .andUsingInsecureDefaultSalt()
                .getDerivedKeyFactoryConfig();

        assertFor_AES128(keyFactoryConfig);
        assertFor_StrongKeyKeyDerivation(keyFactoryConfig);
        assertFor_fastPerRecordDerivation(keyFactoryConfig);
        assertFor_aSaltValueIsSet(keyFactoryConfig);
        assertThat_theCorrectDefaultSaltValueIsSet(keyFactoryConfig);
    }


    @Test
    public void buildingDefaultConfiguration_forFastPerRecordKeyDerivation_usesExpectedSettings() throws Exception {

        final DerivedKeyFactoryConfig keyFactoryConfig = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial()
                .withFastPerRecordDerivation()
                .andUsingInsecureDefaultSalt()
                .getDerivedKeyFactoryConfig();


        assertFor_fastPerRecordDerivation(keyFactoryConfig);
    }

    @Test
    public void buildingDefaultConfiguration_forSlowPerRecordKeyDerivation_usesExpectedSettings() throws Exception {

        final DerivedKeyFactoryConfig keyFactoryConfig = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial()
                .withSlowPerRecordDerivation()
                .andUsingInsecureDefaultSalt()
                .getDerivedKeyFactoryConfig();


        assertFor_slowPerRecordDerivation(keyFactoryConfig);
    }

    @Test
    public void reusingStepsOfTheFactory_isPossible() throws Exception {

        final SymmetricMasterKeySetup.EncryptionAlgorithmSelectionStep.BruteForceProtectionStep.DerivedKeyDerivationWorkFactorSelectionStep
                derivedKeyDerivationWorkFactorSelectionStep = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial();


        final DerivedKeyFactoryConfig cfg1 = derivedKeyDerivationWorkFactorSelectionStep.withSlowPerRecordDerivation().andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig();
        final DerivedKeyFactoryConfig cfg2 = derivedKeyDerivationWorkFactorSelectionStep.withSlowPerRecordDerivation().andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig();
        assertEquals("Using the same factory calls twice yields the same config", cfg1, cfg2);

        final SymmetricMasterKeySetup.EncryptionAlgorithmSelectionStep.BruteForceProtectionStep.DerivedKeyDerivationWorkFactorSelectionStep.SaltSelectionStep saltSelectionStep = derivedKeyDerivationWorkFactorSelectionStep.withSlowPerRecordDerivation();
        assertEquals(saltSelectionStep.andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig(), saltSelectionStep.andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig());
    }

    @Test
    public void theSaltValue_isUsed() throws Exception {

        final SymmetricMasterKeySetup.EncryptionAlgorithmSelectionStep.BruteForceProtectionStep.DerivedKeyDerivationWorkFactorSelectionStep.SaltSelectionStep saltSelectionStep = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial()
                .withSlowPerRecordDerivation();

        assertArrayEquals(saltSelectionStep.andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig().getSaltForMasterKeyDerivation(), saltSelectionStep.andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig().getSaltForMasterKeyDerivation());

        final String salt = "\uD83D\uDCA9";
        assertEquals("salt included in hashcode", saltSelectionStep.andUsingSaltDerivedFromSaltPhrase(salt).getDerivedKeyFactoryConfig().hashCode(), saltSelectionStep.andUsingSaltDerivedFromSaltPhrase(salt).getDerivedKeyFactoryConfig().hashCode());
        assertEquals(saltSelectionStep.andUsingSaltDerivedFromSaltPhrase(salt).getDerivedKeyFactoryConfig(), saltSelectionStep.andUsingSaltDerivedFromSaltPhrase(salt).getDerivedKeyFactoryConfig());
        assertNotEquals(saltSelectionStep.andUsingSaltDerivedFromSaltPhrase(salt).getDerivedKeyFactoryConfig(), saltSelectionStep.andUsingSaltDerivedFromSaltPhrase("another salt").getDerivedKeyFactoryConfig());

    }

    @Test
    public void theDerivcedKeyWorkload_isUsed() throws Exception {

        final DerivedKeyFactoryConfig cfgFastDerivedKey = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial()
                .withFastPerRecordDerivation()
                .andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig();

        final DerivedKeyFactoryConfig cfgSlowDerivedKey = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial()
                .withSlowPerRecordDerivation()
                .andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig();

        assertNotEquals(cfgFastDerivedKey.getDerivedKeyKeyDerivationWorkFactor(), cfgSlowDerivedKey.getDerivedKeyKeyDerivationWorkFactor());
        assertNotEquals(cfgFastDerivedKey.hashCode(), cfgSlowDerivedKey.hashCode());
        assertNotEquals(cfgFastDerivedKey, cfgSlowDerivedKey);
    }

    @Test
    public void theMasterKeyWorkload_isUsed() throws Exception {

        final DerivedKeyFactoryConfig cfgFastMasterKey = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withFastKeyDerivationBasedOnStrongKeyMaterial()
                .withSlowPerRecordDerivation()
                .andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig();

        final DerivedKeyFactoryConfig cfgSlowMasterKey = SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                .forAES128()
                .withKeyDerivationForMasterKeyBasedOnPasswords()
                .withSlowPerRecordDerivation()
                .andUsingInsecureDefaultSalt().getDerivedKeyFactoryConfig();

//FIXME        assertNotEquals(cfgFastMasterKey.getMasterKeyDerivationWorkFactor(), cfgSlowMasterKey.getMasterKeyDerivationWorkFactor());
        assertNotEquals(cfgFastMasterKey.hashCode(), cfgSlowMasterKey.hashCode());
        assertNotEquals(cfgFastMasterKey, cfgSlowMasterKey);
    }

    @Test
    public void buildingConfigurations_isDeterministic() throws Exception {

        Callable<DerivedKeyFactoryConfig> bottledCall = () ->
                SymmetricMasterKeySetup.setupMasterKeyForDeterministicSymmetricKeyDerivation()
                        .forAES128()
                        .withFastKeyDerivationBasedOnStrongKeyMaterial()
                        .withSlowPerRecordDerivation()
                        .andUsingInsecureDefaultSalt()
                        .getDerivedKeyFactoryConfig();

        DerivedKeyFactoryConfig c1 = bottledCall.call();
        DerivedKeyFactoryConfig c2 = bottledCall.call();

        assertEquals("Using the same factory calls twice yields the same config", c1, c2);
    }

    private void assertFor_AES128(DerivedKeyFactoryConfig keyFactoryConfig) {
        assertThat("*AES*-128 is the default algorithm", keyFactoryConfig.getEncryptionAlgorithmIdentifier(), is("AES"));
        assertThat("AES-*128* is the default algorithm", keyFactoryConfig.getMasterKeyLenInBit(), is(128));
    }


    private void assertFor_PasswordBasedKeyDerivation(DerivedKeyFactoryConfig keyFactoryConfig) {
//FIXME        assertThat("Derivation for password based keys use PBKDF2", keyFactoryConfig.getKeyDerivationSecretKeyFactoryIdentifier(), is("PBKDF2WithHmacSHA256"));

//FIXME        assertThat("Derivation for password based keys use PBKDF2 with many rounds", keyFactoryConfig.getMasterKeyDerivationWorkFactor(), is(PBKDF_ROUNDS_FOR_ANTI_BRUTE_FORCE));

        // The work factor must be constant over the lifetime of the library. Else an update of the library would
        // generate different keys for the same input. This would make all data encrypted before inaccessible!
        // To change the work factor explicitly set a different work factor in the caller, not the library.
        //FIXME       assertThat("Derivation work factor must not be changed", keyFactoryConfig.getMasterKeyDerivationWorkFactor(), is(3_141_592));
    }

    private void assertFor_fastPerRecordDerivation(DerivedKeyFactoryConfig keyFactoryConfig) {
        // The work factor must be constant over the lifetime of the library. Else an update of the library would
        // generate different keys for the same input. This would make all data encrypted before inaccessible!
        // To change the work factor explicitly set a different work factor in the caller, not the library.
        assertThat("Derivation for derived key is fast", keyFactoryConfig.getDerivedKeyKeyDerivationWorkFactor(), is(64));
    }

    private void assertFor_slowPerRecordDerivation(DerivedKeyFactoryConfig keyFactoryConfig) {
        // The work factor must be constant over the lifetime of the library. Else an update of the library would
        // generate different keys for the same input. This would make all data encrypted before inaccessible!
        // To change the work factor explicitly set a different work factor in the caller, not the library.
        assertThat("Derivation for derived key is slow", keyFactoryConfig.getDerivedKeyKeyDerivationWorkFactor(), is(100_000));
    }

    private void assertFor_StrongKeyKeyDerivation(DerivedKeyFactoryConfig keyFactoryConfig) {
//FIXME        assertThat("Derivation based on cryptographic strong source material uses PBKDF2", keyFactoryConfig.getKeyDerivationSecretKeyFactoryIdentifier(), is("PBKDF2WithHmacSHA256"));
        // This duplicates the value used in the implementation to detect changes in the implementation.
        //FIXME       assertThat("Derivation based on cryptographic strong source material uses PBKDF2 with only one round", keyFactoryConfig.getMasterKeyDerivationWorkFactor(), is(1));
    }

    private void assertFor_aSaltValueIsSet(DerivedKeyFactoryConfig keyFactoryConfig) {
        assertThat("The salt value is set", keyFactoryConfig.getSaltForMasterKeyDerivation(), notNullValue());
        assertThat("The salt value has a suitable length of >=128bit", keyFactoryConfig.getSaltForMasterKeyDerivation().length, greaterThanOrEqualTo(128 / 8));
    }

    private void assertThat_theCorrectDefaultSaltValueIsSet(DerivedKeyFactoryConfig keyFactoryConfig) throws UnsupportedEncodingException {

        // This duplicates the value used in the implementation to detect changes in the implementation.
        final byte[] defaultSalt = {
                31, 41, 59, 26, 53, 58, 97, 93,
                27, 18, 28, 18, 28, 45, 90, 45
        };
        assertArrayEquals("The default salt value MUST NOT BE CHANGED", keyFactoryConfig.getSaltForMasterKeyDerivation(), defaultSalt);
    }

    */
}