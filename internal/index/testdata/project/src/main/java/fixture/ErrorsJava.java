package fixture;

public final class ErrorsJava {
    public int unresolvedReference() {
        return MissingJavaSymbol.VALUE;
    }

    private int own = 1;
    static void staticUse() { int x = own; im(); this.toString(); }
    void im() {}

    void finals() { final int z = 1; z = 2; }
    final int f = 1;
    void assignField() { f = 2; }

    int missingValue() { return; }
    void unexpectedValue() { return 1; }

    @Override void overridesNothing() {}

    int d; int d;
    void m() {} void m() {}
    void m2(String s) {} void m2(String s) {}
    void locals() { int a; int a; }

    int i = "s"; String s = 1; int j = 1.5; boolean b = 1; char c = "c"; float fl = 1.5; byte by = 200; int fromLong = 1L; String sn = 'c'; int fromNull = null;

    void instantiate() { new JavaAbstractShape(); new JavaShape(); }

    void deref(int x) { x.foo(); }

    int sibling() { return hidden; }
}
abstract class JavaAbstractShape { abstract void area(String unit, int scale); }
interface JavaShape { void draw(); }
class Square extends JavaAbstractShape { }
class Duplicate {}
class Duplicate {}
class JavaSibling { int hidden = 1; }
public class PublicMismatch {}
