public class JavaObfuscationConditionsTest {
    public static void tp(String[] args) {
        if (true) { System.out.println("1"); }
    }

    // FP
    public static void fp(Boolean args) {
        if (!args) { System.out.println("2"); }
    }
}
