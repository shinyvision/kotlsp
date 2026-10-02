// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public abstract class Number {
    public abstract fun toDouble(): Double
    public abstract fun toFloat(): Float
    public abstract fun toLong(): Long
    public abstract fun toInt(): Int
    public abstract fun toShort(): Short
    public abstract fun toByte(): Byte
}
