import java.io.ByteArrayOutputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Compiles on demand inside one long-lived JVM.
 *
 * Protocol, all UTF-8. Request: a line "ARGS <n>" followed by n lines, one
 * compiler argument each. Response: a line "OUTPUT <byteCount>", that many
 * bytes of compiler output, then a line "EXIT <name>".
 */
public final class KotlspCompilerHost {
    public static void main(String[] commandLine) throws Exception {
        // Bound to the descriptor, so redirecting System.out cannot corrupt it.
        OutputStream channel = new BufferedOutputStream(new FileOutputStream(FileDescriptor.out));
        PrintStream realErr = System.err;
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        Class<?> compilerClass;
        Method exec;
		Method structuredExec = null;
		Class<?> messageRendererClass = null;
		String structuredFailure = "";
        try {
            compilerClass = Class.forName("org.jetbrains.kotlin.cli.jvm.K2JVMCompiler");
            exec = compilerClass.getMethod("exec", PrintStream.class, String[].class);
			// The structured transport: the compiler renders every message
			// through a MessageRenderer, so a renderer that emits one record per
			// message yields path, position, severity, and text without parsing
			// the human-readable layout. exec(PrintStream, MessageRenderer,
			// String[]) is the public CLI entry point that accepts a renderer.
			try {
				messageRendererClass = Class.forName("org.jetbrains.kotlin.cli.common.messages.MessageRenderer");
				structuredExec = compilerClass.getMethod("exec", PrintStream.class, messageRendererClass, String[].class);
			} catch (Throwable missingStructuredAPI) {
				structuredExec = null;
				structuredFailure = String.valueOf(missingStructuredAPI);
			}
        } catch (Throwable failure) {
            writeLine(channel, "FATAL " + failure);
            channel.flush();
            return;
        }
        writeLine(channel, structuredExec != null ? "READY structured" : "READY text " + structuredFailure);
        channel.flush();

        // The host must never outlive the server. Reading EOF on stdin covers
        // an orderly shutdown, but a server killed mid-compilation is not
        // reading anything, and the compiler's own threads would keep the JVM
        // alive. A daemon thread watches the parent process instead.
        // The pid is captured once: when the server dies this process is
        // reparented to init or to a subreaper, so asking for the current
        // parent from then on names a live process that never owned it.
        long parentPid = ProcessHandle.current().parent().map(ProcessHandle::pid).orElse(-1L);
        Thread watchdog = new Thread(() -> {
            while (true) {
                if (parentPid < 0 || !ProcessHandle.of(parentPid).map(ProcessHandle::isAlive).orElse(false)) {
                    Runtime.getRuntime().halt(0);
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException interrupted) {
                    return;
                }
            }
        }, "kotlsp-parent-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();

        String line;
        while ((line = input.readLine()) != null) {
            boolean kotlin = line.startsWith("ARGS64 ");
            boolean javaRequest = line.startsWith("JAVAC64 ");
            if (!kotlin && !javaRequest) {
                continue;
            }
			int count = Integer.parseInt(line.substring(line.indexOf(' ') + 1).trim());
			if (count < 0 || count > 300000) throw new IllegalArgumentException("compiler argument count exceeds limit");
            String[] arguments = new String[count];
            for (int n = 0; n < count; n++) {
                String argument = input.readLine();
                if (argument == null) {
                    return;
                }
				arguments[n] = new String(Base64.getDecoder().decode(argument), StandardCharsets.UTF_8);
            }
			BoundedOutput collected = new BoundedOutput(64 * 1024 * 1024);
            PrintStream capture = new PrintStream(collected, true, "UTF-8");
            PrintStream previousOut = System.out;
            PrintStream previousErr = System.err;
            String exit = "INTERNAL_ERROR";
            // The compiler writes to the ambient streams as well as the one it
            // is handed, so both are captured for the duration of the run.
            System.setOut(capture);
            System.setErr(capture);
            try {
                if (javaRequest) {
                    // javac in this same warm JVM: the tool API skips a second
                    // process start, which was the whole cost of the Java pass.
                    javax.tools.JavaCompiler tool = javax.tools.ToolProvider.getSystemJavaCompiler();
                    if (tool == null) {
                        exit = "NO_JAVA_COMPILER";
                    } else {
                        // javac's own text formatter is used deliberately: the
                        // tool API's DiagnosticListener hands out the basic
                        // formatter's wording (fully qualified class names),
                        // while the text output uses the rich formatter whose
                        // wording the fast Java rules predict and reconcile
                        // against. The text output carries the full staged path
                        // and a caret line, so nothing is lost.
                        int code = tool.run(null, collected, collected, arguments);
                        exit = code == 0 ? "OK" : "COMPILATION_ERROR";
                    }
                } else {
                    Object compiler = compilerClass.getDeclaredConstructor().newInstance();
					Object code;
					if (structuredExec != null && messageRendererClass != null) {
						Object renderer = Proxy.newProxyInstance(messageRendererClass.getClassLoader(), new Class<?>[]{messageRendererClass}, (proxy, method, values) -> {
							String name = method.getName();
							if (name.equals("render") && values != null && values.length >= 3) {
								String severity = String.valueOf(values[0]);
								String message = String.valueOf(values[1]);
								Object location = values[2];
								String path = "";
								int sourceLine = 0, sourceColumn = 0;
								if (location != null) {
									try { path = String.valueOf(location.getClass().getMethod("getPath").invoke(location)); } catch (Throwable noPath) { path = ""; }
									try { sourceLine = ((Number) location.getClass().getMethod("getLine").invoke(location)).intValue(); } catch (Throwable noLine) { sourceLine = 0; }
									try { sourceColumn = ((Number) location.getClass().getMethod("getColumn").invoke(location)).intValue(); } catch (Throwable noColumn) { sourceColumn = 0; }
								}
								boolean isError = severity.contains("ERROR") || severity.contains("EXCEPTION");
								boolean isWarning = severity.contains("WARNING");
								if (!isError && !isWarning) return "";
								if (path.isEmpty() || "null".equals(path)) {
									// A finding with no source is a compiler-level failure
									// (a crash, a missing input); it is rendered as text so
									// the pass is rejected with that evidence rather than
									// published as clean. Sourceless warnings are noise.
									return isError ? "e: " + message : "";
								}
								return "KOTLSP_DIAGNOSTIC\t" + Base64.getEncoder().encodeToString(path.getBytes(StandardCharsets.UTF_8)) + "\t" + sourceLine + "\t" + sourceColumn + "\t" + severity + "\t" + Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8));
							}
							if (name.equals("getName")) return "KOTLSP";
							if (method.getReturnType() == String.class) return "";
							if (method.getReturnType() == boolean.class) return false;
							if (method.getReturnType() == int.class) return 0;
							return null;
						});
						code = structuredExec.invoke(compiler, capture, renderer, (Object) arguments);
					} else {
						code = exec.invoke(compiler, capture, (Object) arguments);
					}
                    exit = String.valueOf(code);
                }
            } catch (Throwable failure) {
                failure.printStackTrace(capture);
            } finally {
                System.setOut(previousOut);
                System.setErr(previousErr);
                capture.flush();
            }
			if (collected.truncated()) exit = "OUTPUT_LIMIT";
            byte[] payload = collected.toByteArray();
            writeLine(channel, "OUTPUT " + payload.length);
            channel.write(payload);
            writeLine(channel, "EXIT " + exit);
            channel.flush();
            // The compiler holds large caches per run; returning them promptly
            // keeps a long-lived host from growing without bound.
            realErr.flush();
        }
        // Stdin is closed: the server is gone. Compiler threads must not keep
        // the JVM alive.
        Runtime.getRuntime().halt(0);
    }

    private static void writeLine(OutputStream out, String text) throws java.io.IOException {
        out.write((text + "\n").getBytes(StandardCharsets.UTF_8));
    }

	private static final class BoundedOutput extends OutputStream {
		private final ByteArrayOutputStream delegate = new ByteArrayOutputStream();
		private final int limit;
		private boolean truncated;
		BoundedOutput(int limit) { this.limit = limit; }
		@Override public void write(int value) {
			if (delegate.size() < limit) delegate.write(value); else truncated = true;
		}
		@Override public void write(byte[] value, int offset, int length) {
			int remaining = limit - delegate.size();
			if (remaining > 0) delegate.write(value, offset, Math.min(remaining, length));
			if (length > remaining) truncated = true;
		}
		byte[] toByteArray() { return delegate.toByteArray(); }
		boolean truncated() { return truncated; }
	}
}
