import java.util.List;


public class JavaObfuscationDeclarationsTest {
    // TP
    private int _0xfuscatedVar;
    public String superlongnameThatExceedsTheLimitOfThirtyOneCharacters;

    void w333rd__Name() {
    }

    // FP
    public void processCollection(List<String> collection) {
        for (String i : collection) {
            System.err.println(i);
        }
    }

    public String ValidProperty;

    void ValidMethod() {}

    // The "for" loop must be inside a method
    public void processValidItem(List<String> collection) {
        for (String validItem : collection) {
            System.err.println(validItem);;
        }
    }

    // Try-catch block needs to be inside a method
    public int handleException() {
        try {
        } catch (Exception ex) {
        }
        return _0xfuscatedVar;
    }
}
