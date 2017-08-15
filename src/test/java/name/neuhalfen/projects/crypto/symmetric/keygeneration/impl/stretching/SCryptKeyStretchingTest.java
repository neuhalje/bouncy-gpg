package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.stretching;

import org.junit.Ignore;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;


public class SCryptKeyStretchingTest {
    private final static byte[] SALT_24BIT = new byte[]{0x12, 0x34, 0x5};
    private final static byte[] KEY_256BIT = new byte[256 / 8];


    @Test
    public void scrypt_isDeterministic_withTwoInstances() {
        SCryptKeyStretching.SCryptKeyStretchingParameters fastParams = SCryptKeyStretching.SCryptKeyStretchingParameters.forModeratelyStongInputKeyMaterial();

        final SCryptKeyStretching sut1 = new SCryptKeyStretching(fastParams);
        final SCryptKeyStretching sut2 = new SCryptKeyStretching(fastParams);

        final byte[] testData = "Test".getBytes(StandardCharsets.UTF_8);
        final int KEY_LEN = 128;

        assertThat(sut1.strengthenKey(SALT_24BIT, testData, KEY_LEN), equalTo(sut2.strengthenKey(SALT_24BIT, testData, KEY_LEN)));

    }

    @Test
    public void scrypt_isDeterministic_withSameInstance() {
        SCryptKeyStretching.SCryptKeyStretchingParameters fastParams = SCryptKeyStretching.SCryptKeyStretchingParameters.forModeratelyStongInputKeyMaterial();

        final SCryptKeyStretching sut = new SCryptKeyStretching(fastParams);

        final byte[] testData = "Test".getBytes(StandardCharsets.UTF_8);
        final int KEY_LEN = 128;

        assertThat(sut.strengthenKey(SALT_24BIT, testData, KEY_LEN), equalTo(sut.strengthenKey(SALT_24BIT, testData, KEY_LEN)));

    }

    @Test
    @Ignore("Performance test to estimate the 'quick' setup. Expectation: ~7ms per derivation")
    public void performanceTest_quick() {
        SCryptKeyStretching.SCryptKeyStretchingParameters fastParams = SCryptKeyStretching.SCryptKeyStretchingParameters.forModeratelyStongInputKeyMaterial();

        final SCryptKeyStretching sut = new SCryptKeyStretching(fastParams);

        final byte[] testData = "Test".getBytes(StandardCharsets.UTF_8);
        final int KEY_LEN = 128;

        final long timeStart = System.nanoTime();
        final int ROUNDS = 1_000;
        for (int i = 0; i < ROUNDS; i++) {
            sut.strengthenKey(SALT_24BIT, testData, KEY_LEN);
        }
        final long timeEnd = System.nanoTime();
        final long timeDuration = timeEnd - timeStart;
        System.out.printf("%d kdfs took %dms. (%2.2fms per strengthenKey)", ROUNDS, timeDuration / 1000 / 1000, timeDuration / ROUNDS / 1000 / 1000.0);
    }

    @Test
    @Ignore("Performance test to estimate the 'sensitive' setup. Expectation: ~10s per derivation")
    public void performanceTest_slow() {
        SCryptKeyStretching.SCryptKeyStretchingParameters fastParams = SCryptKeyStretching.SCryptKeyStretchingParameters.forWeakInputKeyMaterial();

        final SCryptKeyStretching sut = new SCryptKeyStretching(fastParams);

        final byte[] testData = "Test".getBytes(StandardCharsets.UTF_8);
        final int KEY_LEN = 128;

        final long timeStart = System.nanoTime();
        final int ROUNDS = 3;
        for (int i = 0; i < ROUNDS; i++) {
            sut.strengthenKey(SALT_24BIT, testData, KEY_LEN);
        }
        final long timeEnd = System.nanoTime();
        final long timeDuration = timeEnd - timeStart;
        System.out.printf("%d kdfs took %ds. (%2.2fs per strengthenKey)", ROUNDS, timeDuration / 1000 / 1000 / 1000, timeDuration / ROUNDS / 1000 / 1000 / 1000.0);
    }

    @Test
    @Ignore("Performance test to estimate the 'recklessly quick' setup. Expectation: less than 1ms per derivation")
    public void performanceTest_quickest() {
        SCryptKeyStretching.SCryptKeyStretchingParameters fastParams = SCryptKeyStretching.SCryptKeyStretchingParameters.forStrongInputKeyMaterial();

        final SCryptKeyStretching sut = new SCryptKeyStretching(fastParams);

        final byte[] testData = "Test".getBytes(StandardCharsets.UTF_8);
        final int KEY_LEN = 128;

        final long timeStart = System.nanoTime();
        final int ROUNDS = 5_000;
        for (int i = 0; i < ROUNDS; i++) {
            sut.strengthenKey(SALT_24BIT, testData, KEY_LEN);
        }
        final long timeEnd = System.nanoTime();
        final long timeDuration = timeEnd - timeStart;
        System.out.printf("%d kdfs took %d ms. (%1.2fms per strengthenKey)", ROUNDS, timeDuration / 1000 / 1000, timeDuration / ROUNDS / 1000 / 1000.0);
    }
}