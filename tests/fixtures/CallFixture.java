package lab;

// Locally authored, harmless bytecode fixture. It is compiled but never run.
public final class CallFixture {
    public interface Action {
        int apply(int value);
    }

    public static final class Box implements Action {
        private int hidden(int value) {
            return value - 1;
        }

        public int direct(int value) {
            return hidden(value);
        }

        public int virtual(int value) {
            return value * 2;
        }

        @Override
        public int apply(int value) {
            return value + 3;
        }
    }

    private static int staticCall(int value) {
        return value + 5;
    }

    private static int sevenArguments(int a, int b, int c, int d, int e, int f, int g) {
        return a + b + c + d + e + f + g;
    }

    public static int guarded(Box box, int value) {
        try {
            return box.virtual(value);
        } catch (IllegalArgumentException rejected) {
            return staticCall(value);
        }
    }

    public static int exercise(Box box, Action action, int input) {
        int direct = box.direct(input);
        int virtualCall = box.virtual(input);
        int interfaceCall = action.apply(input);
        int staticResult = staticCall(input);
        int ranged = sevenArguments(1, 2, 3, 4, 5, 6, 7);
        int switchResult;
        switch (input) {
            case 1:
                switchResult = 10;
                break;
            case 100:
                switchResult = 20;
                break;
            case 1000:
                switchResult = 30;
                break;
            default:
                switchResult = 0;
        }
        byte[] data = new byte[] {
            0x6e, 0x74, 0x71, 0x72, 0x78, 0x6f, 0x70, 0x75,
            0x76, 0x77, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
        };
        return direct + virtualCall + interfaceCall + staticResult + ranged
            + switchResult + data[0];
    }

    private CallFixture() {
    }
}
