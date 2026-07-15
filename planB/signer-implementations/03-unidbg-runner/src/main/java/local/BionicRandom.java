package local;

/** Android Bionic's rand/srand implementation: rand() delegates to random(). */
final class BionicRandom {
    private static final int DEGREE = 31;
    private static final int SEPARATION = 3;

    private final int[] state = new int[DEGREE];
    private int front;
    private int rear;

    BionicRandom() {
        seed(1);
    }

    synchronized void seed(long value) {
        state[0] = (int) value;
        for (int i = 1; i < DEGREE; i++) {
            int previous = state[i - 1];
            int high = previous / 127_773;
            int low = previous % 127_773;
            int next = 16_807 * low - 2_836 * high;
            if (next <= 0) next += 0x7fffffff;
            state[i] = next;
        }
        front = SEPARATION;
        rear = 0;
        for (int i = 0; i < 10 * DEGREE; i++) next();
    }

    synchronized int next() {
        state[front] += state[rear];
        int value = (state[front] >>> 1) & 0x7fffffff;
        front++;
        rear++;
        if (front == DEGREE) front = 0;
        if (rear == DEGREE) rear = 0;
        return value;
    }
}
