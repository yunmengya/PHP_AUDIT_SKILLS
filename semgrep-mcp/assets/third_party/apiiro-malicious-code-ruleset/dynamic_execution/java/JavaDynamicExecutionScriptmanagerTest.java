import javax.script.ScriptEngineManager;
import javax.script.ScriptEngine;

public class JavaDynamicExecutionScriptmanagerTest {
    public static void main(String[] args) throws Exception {
        // TP
        if (true) {
            ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
            engine.eval("...;");
        }
        
        // TP
        otherMethod(new ScriptEngineManager().getEngineByName("JavaScript").eval("...;"));

        // TP
        Object engineObject = new ScriptEngineManager().getEngineByName("JavaScript");
        ((ScriptEngine) engineObject).eval("...;");
        
        // FP
        new ProcessBuilder("kotlin", "-e", "...").start();

        // FP
        ScriptEngine engine3 = new ScriptEngineManager().getEngineByName("JavaScript");
        System.out.println(engine3);

        // FP
        ScriptEngine engine4 = new ScriptEngineManager().getEngineByName("JavaScript");
        engine4.getClass();
    }
    
    static void otherMethod(Object obj) {
        System.out.println("1");
    }
}    
