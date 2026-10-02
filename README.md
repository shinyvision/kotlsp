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
100 milliseconds. Add `-real 40` to measure definition, hover and member
completion at real qualified references in 40 of the project's own Kotlin
files instead of the synthetic fixture.

## Tests

```sh
go test -short ./...   # the inner loop: no real compiler is invoked
go test ./...          # also the compiler-backed tests (javac/K2), when a compiler is found
```

`KOTLSP_COMPILER_TESTS=0` skips the compiler-backed tests without `-short`.

Every test is self-contained: it brings its sources, builds the jars it needs
with `javac`, or reads class files from `testdata`. The tests run with an empty
home, Gradle home and cache directory, so nothing in your `~/.gradle`, `~/.m2`
or caches can change a result. The only things taken from the machine are the
tools: a JDK (`java`, `javac`) and, for the compiler-backed tests, `kotlinc`.
Tests whose tool is missing skip.

## Gradle Kotlin DSL scripts

`*.gradle.kts` files are understood as Gradle compiles them. The build model
reports each project's script classpath, which the index keeps in a source set
of its own (`gradleScript`) so none of it reaches the project's code:

- the Gradle API from the distribution's generated `gradle-api` jar, public
  `org/gradle` packages only, and the Kotlin DSL jars;
- the plugins the build applies (jars named for Gradle or plugins; their
  implementation libraries are left out);
- the type-safe accessors Gradle generated (`implementation(...)`,
  `spotless { }`), merged from Gradle's per-schema directories into one jar
  under `~/.cache/kotlsp/gradle-accessors/`;
- a Kotlin standard library from the project's classpath.

A script has Gradle's implicit imports (the distribution's own list) and its
implicit receivers: the project script template and `Project` in a build
script, `Settings` in `settings.gradle.kts`. Definition on the path in
`project(":x")` opens that project's build file, and completion inside the
quotes offers the build's project paths. Spotless's `kotlinGradle` step formats
scripts when the build configures one. Compiler diagnostics are not run for
scripts.

## Configuration

| Variable | Effect |
| --- | --- |
| `KOTLSP_LOG_FILE=/path` | Same as `--log-file`. |
| `KOTLSP_GOGC=n` | Go GC percentage (default 100): higher trades memory for CPU. |
| `KOTLSP_CACHED_WORKERS=n` | Cached library archives decoded at once during startup (default 4). Fewer lowers the startup memory peak. |
| `KOTLSP_PROFILE_DIR=/dir` | Enables the SIGUSR1/SIGUSR2 profiles described below. |
| `KOTLSP_CPU_PROFILE=/path`, `KOTLSP_CPU_PROFILE_SECONDS=n` | Profile the first n seconds (default 15) of the process. |
| `KOTLSP_HEAP_PROFILE=/path` | Write a heap profile at exit. |
| `KOTLSP_SCAN_TIMING=1` | Print per-archive library scan timings to stderr. |

## Debugging (DAP)

The same binary also speaks the Debug Adapter Protocol. Ask the running
server for a debug endpoint with the `start_debug_server` executeCommand; it
answers with a localhost TCP port. Connect any DAP client (e.g. nvim-dap) and
`launch` with at least `mainClass`; `classPaths`, `sourcePaths`, `cwd`,
`args`, `vmArgs` and `env` are also accepted. The
`intellij.java.resolveClasspath` executeCommand returns the full runtime
classpath of the module owning a given document URI, so clients do not need
to maintain launch configurations by hand.

Debugging runs through the JDK's debugger interface (JDI), so a JDK (not a
JRE) must be on PATH. `attach` connects to a JVM started with
`-agentlib:jdwp=transport=dt_socket,server=y,address=<port>`; it takes `port`,
`host` (or `hostName`) and the same `sourcePaths`, `classPaths` and `cwd` as
`launch`.

Supported: line, function and exception breakpoints, with conditions, hit
conditions and log points; stepping (with step filters that skip JDK and
Kotlin-runtime internals), step-into targets, pause and restart frame;
threads, stack frames and scopes; evaluation, completions, watches and
changing values (locals, fields, array, list and map elements). A condition
that cannot be evaluated stops and says why. Breakpoints reached while an
expression is being evaluated are skipped, with a console note.

Expanding a value reads it from its fields, never by calling a method in the
program: object fields (including inherited and private ones, not static
constants), array elements, and the elements of the JDK's lists, sets, maps
and deques, with their internals under `[raw]`. Boxed numbers show as their
value and enum constants by name. Kotlin's compiler-made locals are hidden,
and an extension receiver shows as `this`. Stack frames from library code
resolve to real sources whenever the dependency's `-sources.jar` sits in the
Gradle or Maven cache, which is what the Gradle `downloadDependencySources`
task in your build is for.

Limits: expressions are evaluated with Java syntax by the JDK's evaluator,
which has no `%`, `&`, `|` or `^` (kotlsp adds `&&` and `||`); data
breakpoints and hot code replace are not supported.

Data and instruction breakpoints are not supported; that is a limitation of
bridging through `jdb` rather than speaking JDWP directly.

## Operational notes

**Kotlin built-ins.** `Any`, `Enum`, `String`, the numeric types, arrays and the
collection interfaces have no class file: the compiler keeps them in
`.kotlin_builtins` resources, and the only place their source exists is the
`kotlin-stdlib` sources jar. When that jar is not in the Gradle/Maven cache the
server falls back to a copy of those declarations embedded in the binary
(`internal/index/builtins/`), written to `~/.cache/kotlsp/builtins/` and indexed
through the same path as a real sources jar. Without either, a `List`, an `Int`
or an enum has no members to complete.

**Sibling modules.** A module's own build output (`build/libs/*.jar`) on another
module's classpath is not indexed as a library: its sources are already in the
index, and a type declared twice resolves to neither.

**References.** Occurrences that were stored unresolved while the project was
still being indexed are resolved by the first `references`/rename on a name and
remembered (`internal/index/late_references.go`). The memory is keyed on the
referencing file's content and on a declaration version, so an edit or a new
declaration discards what it could change. Nothing runs in the background: an
idle server uses no CPU.

**Memory.** After 30 idle seconds the server returns freed pages to the OS.

**Compiler scratch space.** Validation passes compile under
`~/.cache/kotlsp/compiler-work/`, in directories named for the owning process.
A directory whose process has exited -- an editor that kills the server right
after `exit`, a crash -- is removed by the next pass; an unnamed one from an
older build once it is a day old.

**Profiling a session that misbehaves.** Start the server with
`KOTLSP_PROFILE_DIR=/some/dir`, then send `SIGUSR1` for mutex/block/goroutine/heap
profiles, or `SIGUSR2` once to start and again to stop and write a CPU profile.

**Tracing a session started by an editor.** `KOTLSP_LOG_FILE=/path` has the same
effect as `--log-file`, without touching the editor's command line.

**Library metadata.** Kotlin libraries carry a metadata schema version, and the
decoder reads schemas 1.0 to 2.4 (the Kotlin 2.4 standard library is 2.4). Anything
newer is rejected rather than guessed at, and its top-level functions then have no
Kotlin-level signature, so no extension from it applies. A test
(`TestStdlib24MetadataDecodesLikeStdlib21`) decodes the same standard library
classes from a 2.1 and a 2.4 jar and requires identical signatures. When a new
Kotlin release raises the schema, run it against the new jar before raising the
limit in `kotlinMetadataSchemaFor`, and raise `libraryCacheVersion` so cached
libraries are decoded again.

