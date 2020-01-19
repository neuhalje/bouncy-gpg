package name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.howto;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.Feature;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPCompressionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPSymmetricEncryptionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyFlag;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpecBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.Passphrase;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAForEncryptionKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAForSigningKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertNotNull;

public class ExportGeneratedKeysTest {

    private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
    private final static String EMAIL_JULIET = "juliet@example.com";
    private final static String PASSPHRASE = "kj38fdslkjwheoizhsdkjSDGsdfwowei";

    @Before
    public void installBCProvider() {
        BouncyGPG.registerProvider();
    }

    /**
     * Since keeping keys in the GnuPG databases is a very bad idea,
     * I also want to add key generation into my programs workflow.
     * <p>
     * For this a keypair needs to be generated and persisted to my DB.
     **/
    @Test
    public void persistGeneratedKeys() throws NoSuchAlgorithmException, IOException, NoSuchProviderException, SignatureException, PGPException, InvalidAlgorithmParameterException {

        // 1. Create a new keyring with new keys
        KeyringConfig createdKeyRing = createComplexKeyRing(UID_JULIET.getBytes(), PASSPHRASE);

        // 2. Get the persisted keys in a binary format
        ByteArrayOutputStream pubKeyRingBuffer = new ByteArrayOutputStream();
        createdKeyRing.getPublicKeyRings().encode(pubKeyRingBuffer);
        pubKeyRingBuffer.close();
        byte[] publicKey = pubKeyRingBuffer.toByteArray();


        ByteArrayOutputStream secretKeyRingBuffer = new ByteArrayOutputStream();
        createdKeyRing.getSecretKeyRings().encode(secretKeyRingBuffer);
        secretKeyRingBuffer.close();
        byte[] secretKey = secretKeyRingBuffer.toByteArray();

        // 3. load the persisted keys
        InMemoryKeyring memoryKeyring = KeyringConfigs.forGpgExportedKeys(keyId -> PASSPHRASE.toCharArray());
        memoryKeyring.addPublicKey(publicKey);
        memoryKeyring.addSecretKey(secretKey);

        // 4. Assert that the loaded keys are usable
        TestEnAndDecryptionUtil.assertEncryptSignDecryptVerifyOk(memoryKeyring, EMAIL_JULIET);
    }


    /**
     * Since keeping keys in the GnuPG databases is a very bad idea,
     * I also want to add key generation into my programs workflow.
     * <p>
     * For this a keypair needs to be generated and persisted to my DB.
     **/
    @Test
    public void persistAsciiArmoredGeneratedKeys() throws NoSuchAlgorithmException, IOException, NoSuchProviderException, SignatureException, PGPException, InvalidAlgorithmParameterException {

        // 1. Create a new keyring with new keys
        KeyringConfig createdKeyRing = createComplexKeyRing(UID_JULIET.getBytes(), PASSPHRASE);

        // 2. Get the persisted keys in a binary format

        String publicKey;
        try (
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                ArmoredOutputStream armored = new ArmoredOutputStream(buffer);
        ) {
            createdKeyRing.getPublicKeyRings().encode(armored);
            armored.close();
            buffer.close();

            publicKey = new String(buffer.toByteArray(), StandardCharsets.US_ASCII);
            assertThat(publicKey, containsString("BEGIN PGP PUBLIC KEY BLOCK"));
        }

        String secretKey;
        try (
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                ArmoredOutputStream armored = new ArmoredOutputStream(buffer);
        ) {
            createdKeyRing.getSecretKeyRings().encode(armored);
            armored.close();
            buffer.close();

            secretKey = new String(buffer.toByteArray(), StandardCharsets.US_ASCII);
            assertThat(secretKey, containsString("BEGIN PGP PRIVATE KEY BLOCK"));
        }

        // 3. load the persisted keys
        InMemoryKeyring memoryKeyring = KeyringConfigs.forGpgExportedKeys(keyId -> PASSPHRASE.toCharArray());
        memoryKeyring.addPublicKey(publicKey.getBytes());
        memoryKeyring.addSecretKey(secretKey.getBytes());

        // 4. Assert that the loaded keys are usable
        TestEnAndDecryptionUtil.assertEncryptSignDecryptVerifyOk(memoryKeyring, EMAIL_JULIET);
    }


    /**
     * create a keyring with a key and three subkeys from scratch.
     *
     * The key length of 1024 bit is used to speed up the process.
     *
     * 1024 BIT IS NOT SECURE!
     *
     * @param uid        The uid to use for the keys
     * @param passphrase The passphrase to assign to the keys
     */
    private KeyringConfig createComplexKeyRing(byte[] uid, String passphrase)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException {

        // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
        final KeySpec signingSubey = KeySpecBuilder
                .newSpec(RSAForSigningKeyType.withLength(RsaLength.RSA_2048_BIT))
                .allowKeyToBeUsedTo(KeyFlag.SIGN_DATA)
                .withDefaultAlgorithms();

        // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
        final KeySpec authenticationSubey = KeySpecBuilder
                .newSpec(RSAForEncryptionKeyType.withLength(RsaLength.RSA_1024_BIT))
                .allowKeyToBeUsedTo(KeyFlag.AUTHENTICATION)
                .withDefaultAlgorithms();

        // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
        final KeySpec encryptionSubey = KeySpecBuilder
                .newSpec(RSAForEncryptionKeyType.withLength(RsaLength.RSA_1024_BIT))
                .allowKeyToBeUsedTo(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                .withDefaultAlgorithms();

        // 1024 BIT IS NOT SECURE! The key length of 1024 bit is used to speed up the process.
        final KeySpec masterKey = KeySpecBuilder.newSpec(
                RSAForSigningKeyType.withLength(RsaLength.RSA_1024_BIT)
        )
                .allowKeyToBeUsedTo(KeyFlag.CERTIFY_OTHER)
                .withDetailedConfiguration()
                .withPreferredSymmetricAlgorithms(
                        PGPSymmetricEncryptionAlgorithms.recommendedAlgorithms()
                )
                .withPreferredHashAlgorithms(
                        PGPHashAlgorithms.recommendedAlgorithms()
                )
                .withPreferredCompressionAlgorithms(
                        PGPCompressionAlgorithms.recommendedAlgorithms()
                )
                .withFeature(Feature.MODIFICATION_DETECTION)
                .done();

        final KeyringConfig complexKeyRing = BouncyGPG
                .createKeyring()
                .withSubKey(signingSubey)
                .withSubKey(authenticationSubey)
                .withSubKey(encryptionSubey)
                .withMasterKey(masterKey)
                .withPrimaryUserId(uid)
                .withPassphrase(Passphrase.fromString(passphrase))
                .build();

        assertNotNull("A keyring should be created", complexKeyRing);
        return complexKeyRing;
    }
}
