# KotLSP

`kotlsp` is a native Go language server for Kotlin and Java. It is designed
for predictable editor latency: foreground LSP requests only read immutable,
in-memory snapshots while source, Gradle, Maven, JAR, and JDK indexing happens
incrementally in the background.

## How this was made:

I needed a fast and reliable LSP for Kotlin and Java. I’ve tried many, and none
satisfied my requirements. An LSP needs to be fast and feature-complete,
especially if you’re learning a language. IntellIJ’s server is closest on this,
because it’s feature-complete. But calling it slow is an understatement.

So I pointed GPT-5.6 Sol at the IntellIJ server and asked it to build out a
clean-room implementation with focus on speed and implementing all features.
I have not looked at the code myself. I know it is a mess. But it works on my
machine. If it works on yours too: great. If it doesn’t... well, I’m sorry.

So yes. This software is entirely vibe-coded.

## Build

```sh
go build -trimpath -ldflags='-s -w' -o kotlsp ./cmd/kotlsp
```

The default transport is LSP over stdio:

```sh
kotlsp --stdio
```

Use `kotlsp benchmark --workspace /path/to/project` to run the hard latency
gate. Every measured request type must have a worst observed duration below
100 milliseconds.

## Debugging (DAP)

The same binary also speaks the Debug Adapter Protocol. Ask the running
server for a debug endpoint with the `start_debug_server` executeCommand; it
answers with a localhost TCP port. Connect any DAP client (e.g. nvim-dap) and
`launch` with at least `mainClass`; `classPaths`, `sourcePaths`, `cwd`,
`args`, `vmArgs` and `env` are also accepted. The
`intellij.java.resolveClasspath` executeCommand returns the full runtime
classpath of the module owning a given document URI, so clients do not need
to maintain launch configurations by hand.

Debugging runs through the JDK's `jdb`, so a JDK (not a JRE) must be on PATH.
Breakpoints (line, function, exception, conditional, hit conditions and log
points), stepping, scopes, watches, evaluation and call/variable inspection
are supported. Expanding a value inspects it recursively: object fields
(including inherited and private ones), array elements, and the logical
contents of lists, sets and maps rather than their internal fields. Stack
frames from library code resolve to real sources whenever the dependency's
`-sources.jar` sits in the Gradle or Maven cache, which is what the Gradle
`downloadDependencySources` task in your build is for.

Data and instruction breakpoints are not supported; that is a limitation of
bridging through `jdb` rather than speaking JDWP directly.
