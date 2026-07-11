package local;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

final class BionicRandomTest {
    @Test
    void matchesAndroidBionicRandomSequence() {
        BionicRandom random = new BionicRandom();
        random.seed(1_760_000_000L);

        int[] actual = new int[8];
        for (int i = 0; i < actual.length; i++) actual[i] = random.next();

        assertArrayEquals(new int[]{
                708_751_583, 286_884_797, 1_500_726_753, 2_029_542_795,
                1_992_164_192, 89_733_111, 1_363_640_712, 620_674_713
        }, actual);
    }
}
