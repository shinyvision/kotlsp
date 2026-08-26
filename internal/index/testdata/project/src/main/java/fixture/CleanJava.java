package fixture;

/** Compiles without complaint. Any diagnostic here is a false positive. */
public final class CleanJava {
    private final String label;

    public CleanJava(String label) {
        this.label = label;
    }

    public String greet(String name) {
        return label + " " + name;
    }

    // Near misses: each is one step from an error and must stay silent.
    private final int counter;
    private int mutable = 1;
    static int shared = 2;
    static void staticOk() { int x = shared; }
    void assigns() { mutable = 2; int local; local = 1; final int once; once = 2; }
    int returns() { return 1; }
    void voidReturn() { return; }
    @Override public String toString() { return label; }
    long widened = 1; double real = 1; float single = 1.5f; byte small = 100; char ch = 'c'; String nothing = null; Object boxed = 1;
    void loops() { while (true) { break; } }
    int conditional(boolean b) { if (b) return 1; return 2; }
    int throwsUnchecked() { throw new IllegalStateException(); }
    void caught() { try { throw new Exception(); } catch (Exception e) { } }
    void declared() throws Exception { throw new Exception(); }
    void lambda() { Runnable r = () -> { return; }; }
    void anonymous() { Runnable r = new Runnable() { public void run() { int x = mutable; } }; }
    void deref(String s) { s.length(); }
    void instantiate() { new CleanJava("x"); Runnable r = new Runnable() { public void run() {} }; }
    void afterBreak(int x) { switch (x) { case 1: break; case 2: break; default: break; } }
    void ifReturn(boolean b) { if (b) return; mutable = 3; }
    void elseReturn(boolean b) { if (b) mutable = 1; else return; }
}
class ImplementsShape implements Runnable { public void run() {} }
class JavaOverloads { void m() {} void m(int x) {} }
