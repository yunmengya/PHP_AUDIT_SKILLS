public class JavaDynamicExecutionSystemTest {
    public static void main(String[] args) throws Exception {

        // TP
        new ProcessBuilder("java", "-e", "...");
   
        // TP
        new ProcessBuilder("kotlin", "-e", "...");

        // FP
        ProcessBuilder pb = new ProcessBuilder("java", "-jar", "app.jar");
        pb.start();

        // FP
        new ProcessBuilder("echo", "Hello").start();

        // FP
        ProcessBuilder pb2 = new ProcessBuilder("java", "-Xmx1024m", "-Xms512m", "-jar", "app.jar");
        pb2.start();
    }
}
