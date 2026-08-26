package dapfixture;

public final class Debuggee {
    public static void main(String[] args) throws Exception {
        int value = 40;
        value += 2;
        System.out.println(value);
    }
}
