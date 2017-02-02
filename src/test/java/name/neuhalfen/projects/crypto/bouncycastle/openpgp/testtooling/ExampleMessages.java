package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;


public class ExampleMessages {

    /**
     * 2048 bit RSA key 'recipient@example.com'
     * - Trusted by recipient.
     * - Private key held by recipient.
     */
    public final static long PUBKEY_RECIPIENT = 0x54A3DB374F787AB7L;

    /**
     * 2048 bit RSA key 'sender@example.com'
     * - Trusted by recipient.
     * - Private key held by sender.
     */
    public final static long PUBKEY_SENDER = 0x86DAC13816FE6FE2L;

    /**
     * 4096 bit RSA key 'sender2@example.com'
     * - Trusted by recipient.
     * - Private key held by sender.
     */
    public final static long PUBKEY_SENDER_2 = 0xF873744002F1D7C3L;

    /**
     * 2048 bit RSA key 'another_sender@example.com'
     * - Unknown to recipient.
     * - Private key held by sender.
     */
    public final static long PUBKEY_ANOTHER_SENDER = 0x7B7DA94F0876E36EL;


    /**
     * Encrypted-To:    recipient@example.com
     * Signed-By:       sender@example.com
     * Compressed:      false
     */
    public final static String IMPORTANT_QUOTE_SIGNED_NOT_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
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
    public final static String IMPORTANT_QUOTE_SIGNED_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
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
     * Signed-By:       sender@example.com AND another_sender@example.com
     * Compressed:      true
     */
    public final static String IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: GnuPG v2\n" +
            "\n" +
            "hQEMA1Sj2zdPeHq3AQgApWQVGzjMlmIRHNLXh/jtPzwRAredDH/XUQt20zU94pg1\n" +
            "jIE+fYnG8sV37BdzIK7VQW7juOK356Wwq4+f4RSziYiYGJLCKDoQqJSklWYR1e1h\n" +
            "TUlUuZPttv80AXujCvhyWykRAs5GTQRFxQmBAAhwzJAsKDPpVQQ5QAO223+WNi5p\n" +
            "E2JIjEpOVMAMBGPt7nZEPuyHcXNZQPhA4WFFHKZwNGOh6Do64pjNYoCDbzkrCQxa\n" +
            "dvLwuEEEVSoyPbmkWS5/P/QXVgXzR1/+H3gxg/wDp9xSz29hIOZbFLvfZ21PRCnx\n" +
            "xBD0xpmNEGZxRoaf49NWGWlVwEJSK/877ILPvvnmo9LpAbExHiktgLOEuGLQJk2W\n" +
            "bIZft2c8fzOhyHv4vEE6AOupLBNjYbhEXutPPYErxdnNaJ1katUvIHb+VgvxiqLl\n" +
            "2oJL6ZP0/UWj46v7Wl30Pm3EQXFLqaYYIxzuznlRzRx1+LrwjTTKh69uV9ZA+Ook\n" +
            "qMPRbZ5LyXi9h7sk4Vi7rHQ0xJ8sGsa65a0TjojLlnUvz9XN5yceWm0fivsrXETZ\n" +
            "Q86X6DFcBJupjfY3BzLujYGaZVL6a/y3pH+rj+U4Vj4N9EzaYIEGY7Olq5NerTNk\n" +
            "UmqTruJGeU695YKvky+LtHxKdxFQaaCYTgLZyQdLlZ4ElcCPsDpR2zuv4nlrR6aS\n" +
            "dQVDXeyKGplD1keItJ03n9rosn3/mifjJvofsdArtQDytN3QL+lXJsV/VUbjCUeN\n" +
            "RJuM7kspVCA1/iHQIS0qtpygk3QyowZvOGefkmJwA6Y27fWG8/gI6Q8uKuwZ1Ey8\n" +
            "J8KOCnKhaAyFS3TSBRYeIm93tLcam6qiLNbluRBPFPvPpjlr9zqGIoMkEqWOlO9a\n" +
            "tJve376X6t1i8119mDxyv6PdR3WpASy1defkOzS0II6G07ETkrjnhiYPfllQQDOw\n" +
            "uCUg2zb+yFQBr50f6Tkmq5uMCyDd4P1VnEt5GaSSyVl2iwQZLdTC/NtBLu+63iDY\n" +
            "43prtr9ENZogKsnEOy846aPAHo6NAG+1v2IN2BlhoHyLGah8EIbL2CJ9ZHrcxHI8\n" +
            "VKLkA3yMb6z2Fn8I3I4ytDxFfuqd1edrluNH9CfKlTNCtmaOz4sbI8v1NFW5uqvz\n" +
            "FjTH8ZpZ0f8QqOm4bqR0teOg5eLX64w2tO6O79FJPoBnxSq5Gw7lrImrtvQUmygk\n" +
            "2rP9E3RFGJR2z9J/r+aAEqYn9/AICXFfm9/jswxmkBlEXP9kAStgssX82aPTdHLc\n" +
            "xsp6H8mB42WG2QxH59b6oqfkVgaHCt81z7LC/9QBSY1CR0SsHawUL47KRsSw7m7W\n" +
            "Yw==\n" +
            "=OxhG\n" +
            "-----END PGP MESSAGE-----";

    /**
     * Like #IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED but the order of
     * signatures is reversed.
     * <p>
     * Encrypted-To:    recipient@example.com
     * Signed-By:       another_sender@example.com AND  sender@example.com
     * Compressed:      true
     */
    public final static String IMPORTANT_QUOTE_SIGNED_MULTIPLE_V2_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: GnuPG v2\n" +
            "\n" +
            "hQEMA1Sj2zdPeHq3AQgAwGqEeSJpTfWku/djqSOGxmMFk40LTvWBOb8e+T4U+cig\n" +
            "LMMa4iECySrjQAeJdHfL+29uoA98svlizzOUC1SOoUHKvbjnYT8CxH47rMmD1ZrE\n" +
            "qD8678HlRKYQToWTWiDoz85L443BuZedlCe8Vj60pMY5x+i8rElrZTLtAkeGey/3\n" +
            "QjgVJUoW4vgOkFUj8xe/d1/dJzGDG2C+aAZYhQ7IvQghCD8fKSwaJGFrusoEeGff\n" +
            "uWP5xotgxN2rx2L5NycT7QRlyL1OK6jP3RH2dskMB41wsX5rbPFGrBaOpOYR7cdp\n" +
            "Msl1aCCU74DXXUQ0756wyRVS75jUGRTZodNcmvTXR9LpAVxLabsoViv49J2J4brX\n" +
            "XEtc+DMK11CgDGTpbPmSyGj/WUIh0pw7XkVbN4bjvM6ooMV9ZfKv1tGkqrGrT2Bd\n" +
            "bgtyQZLnf7DqK+IJzB/LHyUm/yt1gF9BEgXqiH7AALWkSfN1X6nRGfhIBmS4S9DC\n" +
            "DNU957hZ6fUQY/fWIVWkhoXu7urCtpNbjfRE3a8flSIhT01f5ZER8B4t43oIyXKZ\n" +
            "0yT61pVVLANBVnj01FySPiG0uvNugVyhqxw9uYZwK93X2ri5HC79jibt7vZ8e2X5\n" +
            "7NPovb+BhtUA4PdHr0Ou6A8gyQ/QiHBT78od1R80r0TABcshYRMZGglw5dMX65oK\n" +
            "uQcOdvY1FRaczw/1hmlIVmJxUjTZalk/kH/BzIGLSwiE/Q7MV+myZChzfda0dAtK\n" +
            "rsdaXDHJQp+RJkJ3Unuc3XcyMLfXI/CX7zJgiT2pJ4mvHn9Zh24MZ289CdgUE4NT\n" +
            "t/PM3n0lFVt6tylCi4KI9p36QBzNbhfAyOjaYGBQhRkhPA2ETYyneeoUXQc9LCHu\n" +
            "SG6FxeVSTCVDqA42UC1nrhmVYdF9R8+C9ts7FjUGkdRwi48PmMIBO8TGu+HAoB+o\n" +
            "/fkKq4w5vYMPfpgBDthtR9rO2hMAsqW9XGfaje+QvE5QPmLXLU8ow7MrAI52Wi3r\n" +
            "Tl9vDbZ+aDvCc2f4752p9trAGzKzCRxGxyBxVbNMIqH4TZdhGF44ZEhzujlpZO1a\n" +
            "ysbaExBOk1gtssuQ3pjvXjRI2CDY0DIBCD7NQLp3EdLIGn/Dfqg9VUhOUgLKsA3V\n" +
            "rHtc3R8WcjxmPQWhR/YIsqORKFBBT/8i9gsJIE4L4sC21tFHlByr4CgYZDRfbTcH\n" +
            "okCfv9bES0dqmcvH6ou+SG/2amSdHWOu/rnulAh5Vs5r3xcB+CkNZy3S7jFfCoAh\n" +
            "KXFleR9runn1K4a2Ut17/dSKcVT7qQWSD2pEsx+0vYVPiKWfe0Nn9TETRrdZyA==\n" +
            "=SCj5\n" +
            "-----END PGP MESSAGE-----";

    /**
     * Encrypted-To:    recipient@example.com
     * Signed-By:       another_sender@example.com
     * Compressed:      true
     */
    public final static String IMPORTANT_QUOTE_SIGNED_UNKNOWN_KEY_COMPRESSED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: GnuPG v2\n" +
            "\n" +
            "hQEMA1Sj2zdPeHq3AQgAxIKzL2Q4146ej+4R5xEkYsvzTRbn/itHyDL8BAxkuTXP\n" +
            "bku1p7y87HmgkJmthq1jLq04uGDKvOSo/VAy31KqyDBlnyGXJWIeNvIFAODxb+3K\n" +
            "2eDda+7Ijv/RWagdB20Bn7Duyw+iUlzyiZDoMS9u4/OuN1NbYrgb2wAydmAaBWkl\n" +
            "kK5V2wH7u7lThXAAYc9kaNIbjd9qZlCblNmUW7mKbt0ZnyuHDeTt52Nlgr6WpMMT\n" +
            "SEcODnkpzszRhu9sjuYefALhSxqrU0b1muh1XbGBExa2eSaaA8JOdOFKNYF1Aql9\n" +
            "STETTJKiQNpnruNzb4yJ9Yh7bdS8E3z8n59ATACLwNLA+QGr3E/l0ecbd2eB+Vwe\n" +
            "DwQB6NHhc4xrNyytSlEKBqMo7dpjMEGYwGuSyuTYSlBbq6Bxly3uJhzeR41mrcZt\n" +
            "5Rz9z4qfEh227d/MaQ4SiAmYK0GowXv6zbaTZHzAHPqaLB0V9fHjyOOUWtybCwup\n" +
            "8/O4ZI0FgwTnJ9KBQxq997Q7pz3l2UwFrglOFoYafKqSHFcTMgwajRFDb/3gFWtj\n" +
            "q6Gsylb9ipB9wj3HzyL0w1s58HQ92IhrcXTRLIA4GibbopIBRl1g1FoqVozbPVJp\n" +
            "cva/t4iUxiP0Bh1SHvD4yxR8x7FFkQ94RKBYmmMvtY6sa8p6VsHGYfWpCJqpU7YP\n" +
            "SwkSWGDuehZKfFJ8mP//SUknKV4gWYe2Sh4qvisKlzXt/Is+AMB3mT0hYqZnsj9u\n" +
            "PdXy0lOgmycHZJlaHzbQ+mdHAePRgkfe8WNz3s220L7LYi3DlolBsgYYKZf6FW1A\n" +
            "x60aZxZ2o2p5lnQloEM4a15mx/bsa9tL4b3Hlv0At1m8MwVrLHVv1/tjagOdH0Y7\n" +
            "WVr8a1FkXuriJtcDEUJcyl/cPDvtx3ootxskKZgpAqrJ4dF9woRp+GhaOA==\n" +
            "=UKuw\n" +
            "-----END PGP MESSAGE-----";


    /**
     * Encrypted-To:    recipient@example.com
     * Signed-By:       another_sender@example.com, sender@example.com AND sender2@example.com
     * Compressed:      false
     */
    public final static String IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: GnuPG v2\n" +
            "\n" +
            "hQEMA1Sj2zdPeHq3AQf/TEsFPsGmKA3ajZJqd/hUWTJOjBU57aFOap/MCsNdCGfi\n" +
            "SZzjFcUBRXTqwTrnWvGbjFUkWrzB1cI3oqLlWbK2/dJkJjJ9wFa6fm3CnUfjVh5J\n" +
            "vVUVdzLiGsjr7zz66EGLT7bJcGOfP4c6cvIeb9sghZdxjZi/MMklWaj4dszyb0fH\n" +
            "MheRS2vimxprhvE/3KX+UtaXDG7uM9F/2zT6L37A2ubfxQ51q4YZ4XZZ2iAq0IRG\n" +
            "Q1vYCuJgh03QRY5/Z1L7k/IPlWyqLfXcnNDErZqzUCMievQrixvllLdwgFUYmBck\n" +
            "53GHcBcjPk2KICKR81GhTKHjlONYJGZ3PDY/m8L+qNLqAWeXxxlTrAPuK6s5TZGB\n" +
            "v56WzmyMXVlFo4lUtBPEJHOVdEM68i6XDK1+6Q7wMgXq+VyhXtSRlYGZJE/oEVAm\n" +
            "qgeaWsShdCVYRj/TMRg4UH+V3HDEF/u9IGpGCoX1sWNNkvWss8mskh2LYLWdvojS\n" +
            "QyvB3h4a5aFODJkYTpFYhXgkyFGtzvGxYfClUuTofhlTwNCJzxXfblEBir8CXRqr\n" +
            "uyzT8NYZvbjQYyarhO/CKNr99bb95LYST6mbE++EFAaT7WtONU6HKrY79UMcCRe/\n" +
            "xBkK6xrwvfGsMQ/FLr5QFHeG0kP2+6Va05tvKpvXeizxlX+qIhUuaASZXMNkBy9u\n" +
            "m/ztmbDQwoftxlH5ZvGHTuZSejJNFQGCtHu7CX/voX8vqN4Wb9x+tIKFaLlG7krL\n" +
            "M2ScgnRRNdpdMMXnalP/sjAwxw5H7+BeRH3v/YY5OimbvLqG/MIMtzUvp4OP0z6m\n" +
            "wIC2I+VjDHn1unDMnLEG9elGp+ieJ3GQN7k1mKbXXB2/bH4CViKVg4gorUGXVrGL\n" +
            "qc6p61GZOqB2xkuwNrWgvExVgYQDq1vIbUtlfIKblhwymPMu9Qvrl6SLzmOCG2Am\n" +
            "Du2YpTY92RXD1om9oj9ltrOLqRmj7t5kbt+Z3Xszb3jPHEvQACcNqaETJ4bkuIeh\n" +
            "44bANu0W4erYn5PqA/vTPOrfIwkSQtqaZqivHG3gSZclvMq8ASlPwbIcUlB2duSI\n" +
            "k74nYB5DF2tag6rU4a3gGEE4/+/lDicAnGMO/Ht6YoiKBadfqabflyCAStRFXkz0\n" +
            "Th1jeH72s1QX6DYGypXtzLiyfp0liCIlKGGYX4OhooC3cjU4JdvNeZz/RXSi2UKD\n" +
            "zRDaMvPVOelRgxJB0YA01LZO35j1Tb9ukExBXgRRVOPp2VCU5fh9VlqUC7ocX5mb\n" +
            "/hxhqR4aumGWkoh86nXojSCmTY0SEePZOlRkvFt/8Eyh+Ac1IgxJmXoL9JwcTtDS\n" +
            "L/MX9VUQvAd0BOk+gaabaGKUglqLErXAsBRPxfCswipfjVyZjchbGZ9rXlpjUz7B\n" +
            "4dMxnXtyadbKbCcmzUZ7IFIx0HQCu31FDbzUsxJAbPfpDV9AwbbpgllbFLVuQz8n\n" +
            "kpW4nHsSvwcKKF304PtpJxXbgsUc36nYAB6MgDimiAG4UkCAUFCPi6rVb+ufwFjl\n" +
            "AjYbxxJvBEkoc3nVj+JsJPTfMQycYinuCqiU4v3rH7CFxiP8BoOEtn0am9tjbpFx\n" +
            "wx7K2/4ymM/YR/YsKEGB5J3/t66Ql7G0sw+7xxkySNv0TH5i2PmTJBJk17/bXVB1\n" +
            "oDA9i9YjFVrOmIvxhzEqQ+5rNNV0g9SNrVMnwI7Jjcuh6x8DCU/EYxcNArz63yKz\n" +
            "kMBPoFrbLa0RJYL5FsyLzeoY7Wsy1+TVperBXUAX+/lYfci2Fexgy7wh+mmSrUE7\n" +
            "Ip+6vGrdBzyV09BlCJ3Cu1cA/XT8MkMVZSUvXqCpwQs738amqrhhvMVVpM+L1T3I\n" +
            "ZdNr6uTGuptssLycI9kLpc1ssFleKW3Zw4tJ9cTkHEruKm83o1+us0J3qefMdW0p\n" +
            "2Hbbc79X4kALGkulDCEey3Ykix+KYyCwB7JUhTdPW7OeECUZe+mi7Mg3vwEcbEIC\n" +
            "3pAyJirJYx8LCXFehrWbIkjXR41Y93T0Oj6H28SOVjGLz8Ab6qhJoRFSpNMCShg7\n" +
            "kQcAYvGRCMo1bBdw15LOOdAMEyoNAzMZA9f/rfCmD9nMQQ==\n" +
            "=o6bw\n" +
            "-----END PGP MESSAGE-----";


    /**
     * Encrypted-To:    recipient@example.com
     * Signed-By:       not signed
     * Compressed:      no
     */
    public final static String IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED =
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

    /*
     * Create cipher text by 'echo -n ${IMPORTANT_QUOTE_TEXT} | gpg -e -a -s -r recipient@example.com'
     */
    public final static String IMPORTANT_QUOTE_TEXT = "I love deadlines. I like the whooshing sound they make as they fly by. Douglas Adams";
    public final static String IMPORTANT_QUOTE_SHA256 = "5A341E2D70CB67831E837AC0474E140627913C17113163E47F1207EA5C72F86F";

}
