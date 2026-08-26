package flow;

/**
 * Flow-analysis errors. javac only runs flow analysis over a compilation
 * whose attribution succeeded, so these live apart from the other fixture.
 */
public final class FlowJava {
    int missingReturn() { int x = 1; }

    void unreachable() { return; int y = 1; }

    void throwsChecked() { throw new Exception(); }

    void throwsIo() { throw new java.io.IOException(); }

    int conditional(boolean b) { if (b) return 1; return 2; }

    void caught() { try { throw new Exception(); } catch (Exception e) { } }

    void ifReturn(boolean b) { if (b) return; int z = 1; }

    void finalParam(final int q) { q = 3; }

    void finalLocal() { final int once; once = 1; }
}
