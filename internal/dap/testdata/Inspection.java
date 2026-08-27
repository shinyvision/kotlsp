package dapfixture;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Inspection {
    static class Organ {
        String name = "heart";
    }
    static final class Body extends Organ {
        List<String> parts = new ArrayList<>(List.of("arm", "leg"));
        Map<String, Integer> sizes = new HashMap<>(Map.of("arm", 2, "leg", 4));
        String tag = "body";
        Object missing = null;
    }
    public static void main(String[] args) {
        Body body = new Body();
        int[] nums = {7, 8, 9};
        String text = "scalpel";
        System.out.println("ready " + text);
    }
}
