// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public class Char private constructor() : Comparable<Char> {
    public companion object {
        public const val MIN_VALUE: Char
        public const val MAX_VALUE: Char
        public const val SIZE_BYTES: Int
        public const val SIZE_BITS: Int
    }
    public override fun compareTo(other: Char): Int
    public operator fun plus(other: Int): Char
    public operator fun minus(other: Char): Int
    public operator fun minus(other: Int): Char
    public operator fun inc(): Char
    public operator fun dec(): Char
    public operator fun rangeTo(other: Char): kotlin.ranges.CharRange
    public operator fun rangeUntil(other: Char): kotlin.ranges.CharRange
    public fun toByte(): Byte
    public fun toChar(): Char
    public fun toShort(): Short
    public fun toInt(): Int
    public fun toLong(): Long
    public fun toFloat(): Float
    public fun toDouble(): Double
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}
