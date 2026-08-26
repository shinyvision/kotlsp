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
