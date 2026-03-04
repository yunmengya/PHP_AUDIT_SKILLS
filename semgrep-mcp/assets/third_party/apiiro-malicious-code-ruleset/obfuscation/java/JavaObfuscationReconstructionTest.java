import java.util.Arrays;
import java.util.List;

public class JavaObfuscationReconstructionTest {
    // TP
    List<Object> list = Arrays.asList(72, 101, "o", "oo", 108, 111);

    // FP
    List<Object> list2 = Arrays.asList(72, 101, "o", "oo", 108, "list");  // Avoid mixing lists
}
