// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public abstract class Enum<E : Enum<E>>(name: String, ordinal: Int) : Comparable<E> {
    public companion object {}
    public final val name: String
    public final val ordinal: Int
    public final override fun compareTo(other: E): Int
    public final override fun equals(other: Any?): Boolean
    public final override fun hashCode(): Int
    public override fun toString(): String
}
