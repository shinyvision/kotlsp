// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public class Boolean private constructor() : Comparable<Boolean> {
    public companion object {}
    public operator fun not(): Boolean
    public infix fun and(other: Boolean): Boolean
    public infix fun or(other: Boolean): Boolean
    public infix fun xor(other: Boolean): Boolean
    public override fun compareTo(other: Boolean): Int
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}
