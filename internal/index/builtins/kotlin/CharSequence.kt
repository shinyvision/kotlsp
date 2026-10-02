// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public interface CharSequence {
    public val length: Int
    public operator fun get(index: Int): Char
    public fun subSequence(startIndex: Int, endIndex: Int): CharSequence
}
