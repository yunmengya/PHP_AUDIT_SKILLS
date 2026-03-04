public class JavaObfuscationMethodsMaskingTest {
    String x;

    public JavaObfuscationMethodsMaskingTest() {  // Constructor should match the class name
        StringBuffer sb = new StringBuffer();
        sb.append((char) 72).append((char) 101).append("o").append("oo").append((char) 108).append((char) 111);
        x = sb.toString();
    }
}
