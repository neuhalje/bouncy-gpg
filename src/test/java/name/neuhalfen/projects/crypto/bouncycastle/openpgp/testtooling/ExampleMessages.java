package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;


public class ExampleMessages {

    /**
     * Encrypted-To:    recipient@example.com
     * Signed-By:       sender@example.com
     * Compressed:      false
     */
    public final static String IMPORTANT_QUOTE_NOT_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
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

    /**
     * Encrypted-To:    recipient@example.com
     * Signed-By:       sender@example.com
     * Compressed:      true
     */
    public final static String IMPORTANT_QUOTE_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
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

    /**
     * Encrypted-To:    recipient@example.com
     * Signed-By:       not signed
     * Compressed:      no
     */
    public final static String IMPORTANT_QUOTE_NOT_SIGNED =
            "-----BEGIN PGP MESSAGE-----\n" +
                    "Version: GnuPG v2\n" +
                    "\n" +
                    "hQEMA1Sj2zdPeHq3AQf/RLl46D7Abw+UEKjKW5yS3d5WQVTxXvDKJH8yK7lZUp3a\n" +
                    "ntH9k3QiL/eFLW7/MZlsQqR4aCjHQsyQVBmGzkKeTNjD67ljr7t7BNtrShBLdEWe\n" +
                    "yER8DSnV7F2tf3ba+7udSsNZ/6neTJ6J3/Z+FUmiC+yK3iCExfhbJP4KpvUhEJOt\n" +
                    "LwIspR3vIN6U8u/cLXoret50FNamoksZJfCDWwQ/WVqDa3IqiML2L9P8qOEq3mSy\n" +
                    "QY6KYnVbuf0NIffEkkDn1Yh1KrPn1CUZLURd7s18LduJ2vofmJIIQ57QN1fpw3zf\n" +
                    "MMq1N/vSmZIYAJENHxiSMOm4WrAsQ7db4zCYoLxaTdKFAYjNVw3Xqv3bnnnoUTiQ\n" +
                    "eV/X83fC18A7xv+RqKBWSi1noU759rlgRrY9hZdjJWGkJtxhhayL/qNajF46ZFBl\n" +
                    "YoneVaRCC7tJQA2SRuZtSCRr/8D9iaXKF7bWylgid4/PK+JRFrB57ZZ8+cKYnT07\n" +
                    "znd5CR+Jye1UXfLusnylrlfgKZcCRA==\n" +
                    "=q3RN\n" +
                    "-----END PGP MESSAGE-----";

    /**
     * Encrypted-To:    sender@example.com
     * Signed-By:       not signed
     * Compressed:      no
     */
    public final static String IMPORTANT_QUOTE_NOT_ENCRYPTED_TO_ME =
            "-----BEGIN PGP MESSAGE-----\n" +
                    "Version: GnuPG v2\n" +
                    "\n" +
                    "hQEMA4bawTgW/m/iAQf/YN/QMvkhVXhBqPyzFFdCfPxMRYaOpH9aM0fHaB4B5AgL\n" +
                    "eExiPwmU8s3UcslwUy3C5rRrrQX6YPxH515pExtmKeWlu6yl/x9QJ84n/nCiCRra\n" +
                    "gl3V90jsXNsNjqDDETXrztEPcoZBADpH9TYX7YdmR1lRil5//r5Gq8DTDUo6AX2K\n" +
                    "2IDZ86jsQtg61TJZbdtuN3RqvfuVkvpWOPcPmbvL/NycX/GNbS5XoLnvoqxzguen\n" +
                    "+MPP4NHd4fAeAMYbcBAjrJiIqhJEIQsW8BsngIWJZdRyWsTPKXIdD9Ewl1FjQpRu\n" +
                    "dwrRIgc+TqKBpbHQFiQHURBxCznMqbZGqc6pfqFpedKFAVYuq0n4TYNWmcDPeJTX\n" +
                    "SIEu8Xz9kvE0aBDNJXXAgVgBStBF5CKwhOMh64cm2DbKI8ECcJbs5DYWmxbMQaoY\n" +
                    "khmxsLG7AODfIo777rMtTRPp+1UJvjGAqU0Hebkz79OSeXijvHZ0zpkQexNmSBoK\n" +
                    "Mp1o2aStMLdDWHCgJK1Sc2MSvX6Eyw==\n" +
                    "=GQV9\n" +
                    "-----END PGP MESSAGE-----";
    public final static String IMPORTANT_QUOTE_TEXT = "I love deadlines. I like the whooshing sound they make as they fly by. Douglas Adams";
    public final static String IMPORTANT_QUOTE_SHA256 = "5A341E2D70CB67831E837AC0474E140627913C17113163E47F1207EA5C72F86F";

}
