package e2e;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class App {
    private int counter = 7;
    private String label = "app";

    static class Inner {
        final int depth;
        Inner(int depth) { this.depth = depth; }
        int twice() { return depth * 2; }
    }

    int add(int a, int b) {
        int sum = a + b;
        return sum;
    }

    static int square(int x) {
        return x * x;
    }

    void work() {
        List<String> names = new ArrayList<>();
        names.add("a");
        names.add("b");
        Map<String, Integer> ages = new HashMap<>();
        ages.put("x", 1);
        int[] numbers = {3, 1, 4};
        Inner inner = new Inner(5);
        int total = 0;
        for (int i = 0; i < 5; i++) {
            total += add(i, square(i));
        }
        System.out.println("total=" + total);
        System.err.println("to stderr");
        Runnable r = () -> System.out.println("lambda " + inner.twice());
        r.run();
        try {
            throw new IllegalStateException("caught one");
        } catch (IllegalStateException e) {
            System.out.println("caught " + e.getMessage());
        }
        counter = total;
    }

    public static void main(String[] args) throws Exception {
        App app = new App();
        Thread worker = new Thread(() -> {
            long spin = 0;
            while (!Thread.currentThread().isInterrupted() && spin < 4_000_000_000L) {
                spin++;
            }
        }, "spinner");
        worker.setDaemon(true);
        worker.start();
        app.work();
        System.out.println("args=" + args.length);
        if (args.length > 0 && args[0].equals("loop")) {
            while (true) {
                app.counter++;
            }
        }
        if (args.length > 0 && args[0].equals("crash")) {
            throw new IllegalArgumentException("uncaught one");
        }
    }
}
