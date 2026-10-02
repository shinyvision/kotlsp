import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Formats Kotlin through Spotless's own ktlint adapter, on the classpath the
 * build resolved for it, so the result is exactly what spotlessCheck accepts.
 *
 * Protocol on stdin/stdout, every field a big-endian int length and UTF-8:
 * request = path, editorconfig path ("" for none), overrides ("key=value"
 * lines), text; response = int status (0 formatted, 1 error) and one field.
 * Logging goes to stderr; stdout carries only the protocol.
 */
public final class KotlspFormatHost {
    public static void main(String[] args) throws Exception {
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(FileDescriptor.out)));
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8));
        quietLogging();
        Class<?> adapterClass = Class.forName(args.length > 0 ? args[0] : "com.diffplug.spotless.glue.ktlint.compat.KtLintCompat1Dot0Dot0Adapter");
        Object adapter = adapterClass.getConstructor().newInstance();
        Method format = adapterClass.getMethod("format", String.class, Path.class, Path.class, Map.class);
        DataInputStream in = new DataInputStream(new BufferedInputStream(System.in));
        write(out, 0, "ready");
        while (true) {
            String path, editorConfig, overrides, text;
            try {
                path = read(in);
                editorConfig = read(in);
                overrides = read(in);
                text = read(in);
            } catch (EOFException closed) {
                return;
            }
            Map<String, Object> settings = new LinkedHashMap<>();
            for (String line : overrides.split("\n")) {
                int equals = line.indexOf('=');
                if (equals > 0) {
                    settings.put(line.substring(0, equals), line.substring(equals + 1));
                }
            }
            try {
                Path editorConfigPath = editorConfig.isEmpty() ? null : Paths.get(editorConfig);
                write(out, 0, (String) format.invoke(adapter, text, Paths.get(path), editorConfigPath, settings));
            } catch (InvocationTargetException failure) {
                Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                write(out, 1, cause.getClass().getSimpleName() + ": " + cause.getMessage());
            } catch (Throwable failure) {
                write(out, 1, failure.getClass().getSimpleName() + ": " + failure.getMessage());
            }
        }
    }

    private static String read(DataInputStream in) throws Exception {
        int length = in.readInt();
        if (length < 0 || length > (64 << 20)) {
            throw new EOFException("bad frame");
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return new String(data, StandardCharsets.UTF_8);
    }

    private static void write(DataOutputStream out, int status, String value) throws Exception {
        byte[] data = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(status);
        out.writeInt(data.length);
        out.write(data);
        out.flush();
    }

    /** ktlint logs every file it formats at DEBUG through logback. */
    private static void quietLogging() {
        try {
            Object root = Class.forName("org.slf4j.LoggerFactory").getMethod("getLogger", String.class).invoke(null, "ROOT");
            Class<?> level = Class.forName("ch.qos.logback.classic.Level");
            root.getClass().getMethod("setLevel", level).invoke(root, level.getField("WARN").get(null));
        } catch (Throwable notLogback) {
            // Another binding, or none: its output goes to stderr regardless.
        }
    }
}
