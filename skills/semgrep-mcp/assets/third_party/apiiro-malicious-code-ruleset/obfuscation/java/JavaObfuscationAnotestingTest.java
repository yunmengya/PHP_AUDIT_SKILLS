import java.util.function.Function;

public class JavaObfuscationAnotestingTest {
    public static void main(String[] args) {
        Function<Integer, Function<Integer, Function<Integer, Function<Integer, Integer>>>> f =
            x -> 
                y -> 
                    z -> 
                        w -> x + y + z + w;

        System.out.println(f.apply(1).apply(2).apply(3).apply(4));  // 10
    }
}

