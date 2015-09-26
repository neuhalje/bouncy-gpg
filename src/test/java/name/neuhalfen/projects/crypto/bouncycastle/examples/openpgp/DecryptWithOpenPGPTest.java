package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.StreamDecryption;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.HashingOutputStream;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.hamcrest.CoreMatchers.equalTo;


public class DecryptWithOpenPGPTest {

    private final static String IMPORTANT_QUOTE_NOT_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: GnuPG v1\n" +
            "\n" +
            "hQEMA1Sj2zdPeHq3AQgAoY5qm/9RNyWpvqR+fOn/VsJSXDzaqeYgR34xAdu1Yvqq\n" +
            "uGsLhVG1VG5WJlZPkh8WtFvMmOUfaMi5yKqGiKA1KP+xuiH5KWjkiSEnBnzpA0o4\n" +
            "1JrwHMBqdrHEDDGityOG+uDuMIA9ou0RJnSDHCTEtTrK2hcV5a7b4z7z9kFYlkq9\n" +
            "x1oFCUFt8BRMrNO6EQMHa2apMb2LLK//QYuscg3GTm6Vi9Pt6xKeaAam4ygLmD5b\n" +
            "nTHBys0GlXZV2stD3CRjW4UdJ89XjdjDin0GH4ZWfbWby4gqNbap03Epsz1qCNDF\n" +
            "WlQSeuxHZcn0Va3jNyFXGsWkVFTrPEOEG15B5OKdsdLA8wGZLLys06GIlqvcpjXu\n" +
            "pmRUoj1vusDFrhhhzUpBD3SlHLUWnYs5UYK6rB8ZUeF3MjRWzjT8xctGgR2JG2Jg\n" +
            "hpYQZai9fNQ8hefhMdtW4TfiqTpNNmtTCgx7RSvDidOxHI6N9v5HR8WNQlE05ogr\n" +
            "wJ5l5emgWKD9cVJR5VVM/GXjffG5Mmncr7HHy9z0P/5PJkocTxtVR2QR9vyT0f/X\n" +
            "ds7yS9w+WPXMbx3MtU07X/5mjaWpC5ZoCjypHJfk1GjW65eZzMi7NDvsoSLCFh3L\n" +
            "5yOrvvmNWBLcgTQiIdc7CMjkRCtdpjWLgdJNyn7HIiy5CHg9iggiPLt5xr6As7Iw\n" +
            "befmmkBk6Uy5ft4NFXs70oetXZLPDLFokAzfes3E0pUMLYgr4ZzIj+cdINs4+L3d\n" +
            "80nqx4TKgIQvNPgtPwKUUAJE3N7zW9hD0HpJjG5pgvvmsARp831U1DCZGtjE18du\n" +
            "+19nGVuPU9nFKEW/VMofxJdb2tXp083i3ZUEYgcNYcB22kM17xRmJ239BRnBa2BJ\n" +
            "MAA9m9UBHrWopfDACZF0mjpMvQdr68AiOTHtrxFgtou/axa8wg==\n" +
            "=xVAW\n" +
            "-----END PGP MESSAGE-----\n";

    private final static String IMPORTANT_QUOTE_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: GnuPG v1\n" +
            "\n" +
            "hQEMA1Sj2zdPeHq3AQf8CPN1Fbg0HXQHSFzONYZyxkabSAMgIzXf/VOp+FWER0A1\n" +
            "o9RCajzYwbcSZCLpg9T+xbCJ3nS+ndFs0cx7MSevBSk1tVriiv/Vn0Odj17keX+a\n" +
            "YlRkfk1n10JWKrJwS3BJx6JuK8uRmZwpqr+IqFlMu0TJH7rNAfGwbSFgJrHUd4Je\n" +
            "ieA8eTXkjnassNTvMlaZVmVi//BjpzK9o91r0zWvp66k6v2uZML0SQT3E6xDTWBM\n" +
            "WtHuJqdaAziShn27w9M26zOO9UEpVhjz8fDQAetdMEp1z6p6BL/2p3jayOMeIIcq\n" +
            "iCTB0dRgqakBHnY/izzsCXYr3xigchi+gXBAjvzoM9LA+wFSRA3v+jJu6NK2ackD\n" +
            "W4gFPNuhI1IoIt9cjP9hZS7rb1stHrQ0QFMwTM/2djRJSw6jjhi7zSnPL61FOdtY\n" +
            "NaxNPUv+Ab+QvmM/0notYfNQZIdpaDpJ6jOuXe2qJ2xH4oAGOqqscTO9jB2p6ykQ\n" +
            "JtRq4BCcfMk8RddScpZzSK9JA1jslzpXbYAFWqvMVDSYwHGSP8FgAJUMbI7ZdNGt\n" +
            "nRXDxDhBdfR7ix1NcYwg+g1f7qf3j2cgYhgMVajSqGSW84HfUOcNVSQz9M+GrWtS\n" +
            "nwzrqU3ar1qg5TcaPc2NE8b5SGh/3afG+kpkVufUqPPgAtfSMxgB9d9fqdqtO8zp\n" +
            "jqC6lrR63jXiH1CovCUPJ65jJou6EZ+vbjx9ISxMqYuqBSuafxvPsAhb2fu5NsJW\n" +
            "Y4BCBhe3gFr40bhlnK7P1+ot3XYLm01GTTI1CmDLlQIH2aSozhsRE/ahc/1xf75U\n" +
            "jidHHK5iPFfBAo2ouCmb6HRhPUOzMHuMHCMRqScOSI/Css6BvLaqoHCUBwzN8Dhb\n" +
            "kfkE8g9Jm9QfsIaCwfcTqJslO22BSIANmm2Ho8vevPzS0uTxnugoRaA6r0qw\n" +
            "=dQ4L\n" +
            "-----END PGP MESSAGE-----";

    private final static String IMPORTANT_QUOTE_SHA256 = "5A341E2D70CB67831E837AC0474E140627913C17113163E47F1207EA5C72F86F";
    private final static String IMPORTANT_QUOTE_TEXT = "I love deadlines. I like the whooshing sound they make as they fly by. Douglas Adams";

    @Test
    public void decryptingAndVerifying_smallAmountsOfData_correctlyDecryptsUncompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {
        StreamDecryption sut = new DecryptWithOpenPGP(Configs.buildConfigForDecryptionFromResources());

        ByteArrayOutputStream res = new ByteArrayOutputStream();
        sut.decryptAndVerify(new ByteArrayInputStream(IMPORTANT_QUOTE_COMPRESSED.getBytes("UTF-8")), res);

        String decryptedQuote = res.toString("UTF-8");
        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
        //
    }

    @Test
    public void decryptingAndVerifyingViaHashing_smallAmountsOfData_correctlyDecryptsUncompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {
        StreamDecryption sut = new DecryptWithOpenPGP(Configs.buildConfigForDecryptionFromResources());
        HashingOutputStream result = HashingOutputStream.sha256();

        sut.decryptAndVerify(new ByteArrayInputStream(IMPORTANT_QUOTE_COMPRESSED.getBytes("UTF-8")), result);

        String decryptedQuoteHash = result.toString();
        Assert.assertThat(decryptedQuoteHash, equalTo(IMPORTANT_QUOTE_SHA256));
        //
    }

    @Test(expected = SignatureException.class)
    public void decryptingTamperedCiphertext_fails() throws IOException, SignatureException, NoSuchAlgorithmException {
        StreamDecryption sut = new DecryptWithOpenPGP(Configs.buildConfigForDecryptionFromResources());
        HashingOutputStream result = HashingOutputStream.sha256();

        byte[] buf = IMPORTANT_QUOTE_NOT_COMPRESSED.getBytes("UTF-8");

        // tamper
        buf[666]++;

        sut.decryptAndVerify(new ByteArrayInputStream(buf), result);
    }

}