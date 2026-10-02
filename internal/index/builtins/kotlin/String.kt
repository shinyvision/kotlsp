// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public class String : Comparable<String>, CharSequence {
    public companion object {}
    public operator fun plus(other: Any?): String
    public override val length: Int
    public override fun get(index: Int): Char
    public override fun subSequence(startIndex: Int, endIndex: Int): CharSequence
    public override fun compareTo(other: String): Int
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}
