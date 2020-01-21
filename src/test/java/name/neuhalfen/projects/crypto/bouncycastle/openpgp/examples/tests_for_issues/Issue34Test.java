package name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.tests_for_issues;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.io.Streams;
import org.junit.Ignore;
import org.junit.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.time.Instant;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class Issue34Test {

    private final static String PUBLIC_KEY =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                    "Version: BCPG C# v2.0.0.0\n" +
                    "\n" +
            "mI0EXXjmnwEEAMF/BtQCgedgaALZfSx+QEYKJXl3+N5Lk3I40AoSiPdQI1WIw7Yg\n" +
            "+jWmVAwvTxI9CSe/37bASd1I30PGonKKB7FLTnCBwGlkUIeAXp35qu1QVo6v/o9V\n" +
            "dESisXz+wtH4Vs77UV8qICnonGze2CuVUKprzFS3oKOEgv1NyONBjQTtABEBAAG0\n" +
            "LnR1c2VwMjAxOXhkczIwMTl2Y2NiaXNoZXJld2gyZGFsb2Y3ZXhwY29tcHNjb3OI\n" +
            "ogQQAQIADAUCXXjmnwWJAMB6AgAKCRBlpeBT3lPwt9g7A/9y+FRq7GKhsdBHCB/l\n" +
            "pqeFyTU0g7sOKF1CPZnDLrb2uYSQAgQ8HSvoQ+oXf45I1peq3FS+FqYmfE9Ok5qM\n" +
            "CU6ObYYX3DbBQaSZDM+pplhURJYV6HnuXVQ4TosDV0+d8cjD3kr+gFFAvT5ePa4F\n" +
            "0BdJss42Zi06n8CGNicFmVWPYQ==\n" +
            "=ArbK\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    // needed some formatting and cleanup
    private final static String PUBLIC_KEY_FROM_TICKET = "\n" +
            "\n" +
            "    -----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "    Version: BCPG C# v2.0.0.0\n" +
            "\n" +
            "    mI0EXXjmnwEEAMF/BtQCgedgaALZfSx+QEYKJXl3+N5Lk3I40AoSiPdQI1WIw7Yg\n" +
            "    +jWmVAwvTxI9CSe/37bASd1I30PGonKKB7FLTnCBwGlkUIeAXp35qu1QVo6v/o9V\n" +
            "    dESisXz+wtH4Vs77UV8qICnonGze2CuVUKprzFS3oKOEgv1NyONBjQTtABEBAAG0\n" +
            "    LnR1c2VwMjAxOXhkczIwMTl2Y2NiaXNoZXJld2gyZGFsb2Y3ZXhwY29tcHNjb3OI\n" +
            "    ogQQAQIADAUCXXjmnwWJAMB6AgAKCRBlpeBT3lPwt9g7A/9y+FRq7GKhsdBHCB/l\n" +
            "    pqeFyTU0g7sOKF1CPZnDLrb2uYSQAgQ8HSvoQ+oXf45I1peq3FS+FqYmfE9Ok5qM\n" +
            "    CU6ObYYX3DbBQaSZDM+pplhURJYV6HnuXVQ4TosDV0+d8cjD3kr+gFFAvT5ePa4F\n" +
            "    0BdJss42Zi06n8CGNicFmVWPYQ==\n" +
            "    =ArbK\n" +
            "    -----END PGP PUBLIC KEY `BLOCK-----\n";
    private final static String UID = "tusep2019xds2019vccbisherewh2dalof7expcompscos";
    private final static long KEY_ID = 0x65A5E053DE53F0B7L;


    /**
     * A user reported an error with a specific key. It turned out, that the key does not have
     * any keyflags set. So this is a workaround.
     */
    @Test
    @Ignore("This test demonstrates a workaround and does not test a feature")
    public  void assertIssue34_workaround_works()
            throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

        final ByteArrayOutputStream result = new ByteArrayOutputStream();

        InMemoryKeyring keyring = KeyringConfigs.forGpgExportedKeys(keyId -> null);
        keyring.addPublicKey(PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII));

        assertTrue("The key should be imported with the correct key ID", keyring.getPublicKeyRings().contains(KEY_ID));

        try (
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384);
                final OutputStream outputStream = BouncyGPG
                        .encryptToStream()
                        .withConfig(keyring).withKeySelectionStrategy(new Rfc4880KeySelectionStrategy(Instant.parse("2020-01-21T09:00:00Z")){
                            // The key does not have set any of KeyFlag.ENCRYPT_COMMS or the KeyFlag.ENCRYPT_STORAGE
                            protected boolean isEncryptionKey(PGPPublicKey publicKey){return true;}
                        })
                        .withStrongAlgorithms()
                        .toRecipient(UID)
                        .andDoNotSign()
                        .binaryOutput()
                        .andWriteTo(bufferedOutputStream);

                final InputStream is = new ByteArrayInputStream(
                        ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes())
        ) {
            Streams.pipeAll(is, outputStream);
        }

        // Should not err - so Id we are here, everything is OK
    }
}
