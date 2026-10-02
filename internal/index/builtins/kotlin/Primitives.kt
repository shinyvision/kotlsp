// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public class Byte private constructor() : Number(), Comparable<Byte> {
    public companion object {
        public const val MIN_VALUE: Byte
        public const val MAX_VALUE: Byte
        public const val SIZE_BYTES: Int
        public const val SIZE_BITS: Int
    }
    public operator fun compareTo(other: Byte): Int
    public operator fun compareTo(other: Short): Int
    public operator fun compareTo(other: Int): Int
    public operator fun compareTo(other: Long): Int
    public operator fun compareTo(other: Float): Int
    public operator fun compareTo(other: Double): Int
    public operator fun plus(other: Byte): Int
    public operator fun plus(other: Short): Int
    public operator fun plus(other: Int): Int
    public operator fun plus(other: Long): Long
    public operator fun plus(other: Float): Float
    public operator fun plus(other: Double): Double
    public operator fun minus(other: Byte): Int
    public operator fun minus(other: Short): Int
    public operator fun minus(other: Int): Int
    public operator fun minus(other: Long): Long
    public operator fun minus(other: Float): Float
    public operator fun minus(other: Double): Double
    public operator fun times(other: Byte): Int
    public operator fun times(other: Short): Int
    public operator fun times(other: Int): Int
    public operator fun times(other: Long): Long
    public operator fun times(other: Float): Float
    public operator fun times(other: Double): Double
    public operator fun div(other: Byte): Int
    public operator fun div(other: Short): Int
    public operator fun div(other: Int): Int
    public operator fun div(other: Long): Long
    public operator fun div(other: Float): Float
    public operator fun div(other: Double): Double
    public operator fun rem(other: Byte): Int
    public operator fun rem(other: Short): Int
    public operator fun rem(other: Int): Int
    public operator fun rem(other: Long): Long
    public operator fun rem(other: Float): Float
    public operator fun rem(other: Double): Double
    public operator fun inc(): Byte
    public operator fun dec(): Byte
    public operator fun unaryPlus(): Int
    public operator fun unaryMinus(): Int
    public operator fun rangeTo(other: Byte): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Byte): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Short): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Short): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Int): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Int): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Long): kotlin.ranges.LongRange
    public operator fun rangeUntil(other: Long): kotlin.ranges.LongRange
    public override fun toByte(): Byte
    public override fun toShort(): Short
    public override fun toInt(): Int
    public override fun toLong(): Long
    public override fun toFloat(): Float
    public override fun toDouble(): Double
    public fun toChar(): Char
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}

public class Short private constructor() : Number(), Comparable<Short> {
    public companion object {
        public const val MIN_VALUE: Short
        public const val MAX_VALUE: Short
        public const val SIZE_BYTES: Int
        public const val SIZE_BITS: Int
    }
    public operator fun compareTo(other: Byte): Int
    public operator fun compareTo(other: Short): Int
    public operator fun compareTo(other: Int): Int
    public operator fun compareTo(other: Long): Int
    public operator fun compareTo(other: Float): Int
    public operator fun compareTo(other: Double): Int
    public operator fun plus(other: Byte): Int
    public operator fun plus(other: Short): Int
    public operator fun plus(other: Int): Int
    public operator fun plus(other: Long): Long
    public operator fun plus(other: Float): Float
    public operator fun plus(other: Double): Double
    public operator fun minus(other: Byte): Int
    public operator fun minus(other: Short): Int
    public operator fun minus(other: Int): Int
    public operator fun minus(other: Long): Long
    public operator fun minus(other: Float): Float
    public operator fun minus(other: Double): Double
    public operator fun times(other: Byte): Int
    public operator fun times(other: Short): Int
    public operator fun times(other: Int): Int
    public operator fun times(other: Long): Long
    public operator fun times(other: Float): Float
    public operator fun times(other: Double): Double
    public operator fun div(other: Byte): Int
    public operator fun div(other: Short): Int
    public operator fun div(other: Int): Int
    public operator fun div(other: Long): Long
    public operator fun div(other: Float): Float
    public operator fun div(other: Double): Double
    public operator fun rem(other: Byte): Int
    public operator fun rem(other: Short): Int
    public operator fun rem(other: Int): Int
    public operator fun rem(other: Long): Long
    public operator fun rem(other: Float): Float
    public operator fun rem(other: Double): Double
    public operator fun inc(): Short
    public operator fun dec(): Short
    public operator fun unaryPlus(): Int
    public operator fun unaryMinus(): Int
    public operator fun rangeTo(other: Byte): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Byte): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Short): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Short): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Int): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Int): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Long): kotlin.ranges.LongRange
    public operator fun rangeUntil(other: Long): kotlin.ranges.LongRange
    public override fun toByte(): Byte
    public override fun toShort(): Short
    public override fun toInt(): Int
    public override fun toLong(): Long
    public override fun toFloat(): Float
    public override fun toDouble(): Double
    public fun toChar(): Char
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}

public class Int private constructor() : Number(), Comparable<Int> {
    public companion object {
        public const val MIN_VALUE: Int
        public const val MAX_VALUE: Int
        public const val SIZE_BYTES: Int
        public const val SIZE_BITS: Int
    }
    public operator fun compareTo(other: Byte): Int
    public operator fun compareTo(other: Short): Int
    public operator fun compareTo(other: Int): Int
    public operator fun compareTo(other: Long): Int
    public operator fun compareTo(other: Float): Int
    public operator fun compareTo(other: Double): Int
    public operator fun plus(other: Byte): Int
    public operator fun plus(other: Short): Int
    public operator fun plus(other: Int): Int
    public operator fun plus(other: Long): Long
    public operator fun plus(other: Float): Float
    public operator fun plus(other: Double): Double
    public operator fun minus(other: Byte): Int
    public operator fun minus(other: Short): Int
    public operator fun minus(other: Int): Int
    public operator fun minus(other: Long): Long
    public operator fun minus(other: Float): Float
    public operator fun minus(other: Double): Double
    public operator fun times(other: Byte): Int
    public operator fun times(other: Short): Int
    public operator fun times(other: Int): Int
    public operator fun times(other: Long): Long
    public operator fun times(other: Float): Float
    public operator fun times(other: Double): Double
    public operator fun div(other: Byte): Int
    public operator fun div(other: Short): Int
    public operator fun div(other: Int): Int
    public operator fun div(other: Long): Long
    public operator fun div(other: Float): Float
    public operator fun div(other: Double): Double
    public operator fun rem(other: Byte): Int
    public operator fun rem(other: Short): Int
    public operator fun rem(other: Int): Int
    public operator fun rem(other: Long): Long
    public operator fun rem(other: Float): Float
    public operator fun rem(other: Double): Double
    public operator fun inc(): Int
    public operator fun dec(): Int
    public operator fun unaryPlus(): Int
    public operator fun unaryMinus(): Int
    public operator fun rangeTo(other: Byte): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Byte): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Short): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Short): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Int): kotlin.ranges.IntRange
    public operator fun rangeUntil(other: Int): kotlin.ranges.IntRange
    public operator fun rangeTo(other: Long): kotlin.ranges.LongRange
    public operator fun rangeUntil(other: Long): kotlin.ranges.LongRange
    public infix fun shl(bitCount: Int): Int
    public infix fun shr(bitCount: Int): Int
    public infix fun ushr(bitCount: Int): Int
    public infix fun and(other: Int): Int
    public infix fun or(other: Int): Int
    public infix fun xor(other: Int): Int
    public fun inv(): Int
    public override fun toByte(): Byte
    public override fun toShort(): Short
    public override fun toInt(): Int
    public override fun toLong(): Long
    public override fun toFloat(): Float
    public override fun toDouble(): Double
    public fun toChar(): Char
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}

public class Long private constructor() : Number(), Comparable<Long> {
    public companion object {
        public const val MIN_VALUE: Long
        public const val MAX_VALUE: Long
        public const val SIZE_BYTES: Int
        public const val SIZE_BITS: Int
    }
    public operator fun compareTo(other: Byte): Int
    public operator fun compareTo(other: Short): Int
    public operator fun compareTo(other: Int): Int
    public operator fun compareTo(other: Long): Int
    public operator fun compareTo(other: Float): Int
    public operator fun compareTo(other: Double): Int
    public operator fun plus(other: Byte): Long
    public operator fun plus(other: Short): Long
    public operator fun plus(other: Int): Long
    public operator fun plus(other: Long): Long
    public operator fun plus(other: Float): Float
    public operator fun plus(other: Double): Double
    public operator fun minus(other: Byte): Long
    public operator fun minus(other: Short): Long
    public operator fun minus(other: Int): Long
    public operator fun minus(other: Long): Long
    public operator fun minus(other: Float): Float
    public operator fun minus(other: Double): Double
    public operator fun times(other: Byte): Long
    public operator fun times(other: Short): Long
    public operator fun times(other: Int): Long
    public operator fun times(other: Long): Long
    public operator fun times(other: Float): Float
    public operator fun times(other: Double): Double
    public operator fun div(other: Byte): Long
    public operator fun div(other: Short): Long
    public operator fun div(other: Int): Long
    public operator fun div(other: Long): Long
    public operator fun div(other: Float): Float
    public operator fun div(other: Double): Double
    public operator fun rem(other: Byte): Long
    public operator fun rem(other: Short): Long
    public operator fun rem(other: Int): Long
    public operator fun rem(other: Long): Long
    public operator fun rem(other: Float): Float
    public operator fun rem(other: Double): Double
    public operator fun inc(): Long
    public operator fun dec(): Long
    public operator fun unaryPlus(): Long
    public operator fun unaryMinus(): Long
    public operator fun rangeTo(other: Byte): kotlin.ranges.LongRange
    public operator fun rangeUntil(other: Byte): kotlin.ranges.LongRange
    public operator fun rangeTo(other: Short): kotlin.ranges.LongRange
    public operator fun rangeUntil(other: Short): kotlin.ranges.LongRange
    public operator fun rangeTo(other: Int): kotlin.ranges.LongRange
    public operator fun rangeUntil(other: Int): kotlin.ranges.LongRange
    public operator fun rangeTo(other: Long): kotlin.ranges.LongRange
    public operator fun rangeUntil(other: Long): kotlin.ranges.LongRange
    public infix fun shl(bitCount: Int): Long
    public infix fun shr(bitCount: Int): Long
    public infix fun ushr(bitCount: Int): Long
    public infix fun and(other: Long): Long
    public infix fun or(other: Long): Long
    public infix fun xor(other: Long): Long
    public fun inv(): Long
    public override fun toByte(): Byte
    public override fun toShort(): Short
    public override fun toInt(): Int
    public override fun toLong(): Long
    public override fun toFloat(): Float
    public override fun toDouble(): Double
    public fun toChar(): Char
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}

public class Float private constructor() : Number(), Comparable<Float> {
    public companion object {
        public const val MIN_VALUE: Float
        public const val MAX_VALUE: Float
        public const val SIZE_BYTES: Int
        public const val SIZE_BITS: Int
        public const val POSITIVE_INFINITY: Float
        public const val NEGATIVE_INFINITY: Float
        public const val NaN: Float
    }
    public operator fun compareTo(other: Byte): Int
    public operator fun compareTo(other: Short): Int
    public operator fun compareTo(other: Int): Int
    public operator fun compareTo(other: Long): Int
    public operator fun compareTo(other: Float): Int
    public operator fun compareTo(other: Double): Int
    public operator fun plus(other: Byte): Float
    public operator fun plus(other: Short): Float
    public operator fun plus(other: Int): Float
    public operator fun plus(other: Long): Float
    public operator fun plus(other: Float): Float
    public operator fun plus(other: Double): Double
    public operator fun minus(other: Byte): Float
    public operator fun minus(other: Short): Float
    public operator fun minus(other: Int): Float
    public operator fun minus(other: Long): Float
    public operator fun minus(other: Float): Float
    public operator fun minus(other: Double): Double
    public operator fun times(other: Byte): Float
    public operator fun times(other: Short): Float
    public operator fun times(other: Int): Float
    public operator fun times(other: Long): Float
    public operator fun times(other: Float): Float
    public operator fun times(other: Double): Double
    public operator fun div(other: Byte): Float
    public operator fun div(other: Short): Float
    public operator fun div(other: Int): Float
    public operator fun div(other: Long): Float
    public operator fun div(other: Float): Float
    public operator fun div(other: Double): Double
    public operator fun rem(other: Byte): Float
    public operator fun rem(other: Short): Float
    public operator fun rem(other: Int): Float
    public operator fun rem(other: Long): Float
    public operator fun rem(other: Float): Float
    public operator fun rem(other: Double): Double
    public operator fun inc(): Float
    public operator fun dec(): Float
    public operator fun unaryPlus(): Float
    public operator fun unaryMinus(): Float
    public override fun toByte(): Byte
    public override fun toShort(): Short
    public override fun toInt(): Int
    public override fun toLong(): Long
    public override fun toFloat(): Float
    public override fun toDouble(): Double
    public fun toChar(): Char
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}

public class Double private constructor() : Number(), Comparable<Double> {
    public companion object {
        public const val MIN_VALUE: Double
        public const val MAX_VALUE: Double
        public const val SIZE_BYTES: Int
        public const val SIZE_BITS: Int
        public const val POSITIVE_INFINITY: Double
        public const val NEGATIVE_INFINITY: Double
        public const val NaN: Double
    }
    public operator fun compareTo(other: Byte): Int
    public operator fun compareTo(other: Short): Int
    public operator fun compareTo(other: Int): Int
    public operator fun compareTo(other: Long): Int
    public operator fun compareTo(other: Float): Int
    public operator fun compareTo(other: Double): Int
    public operator fun plus(other: Byte): Double
    public operator fun plus(other: Short): Double
    public operator fun plus(other: Int): Double
    public operator fun plus(other: Long): Double
    public operator fun plus(other: Float): Double
    public operator fun plus(other: Double): Double
    public operator fun minus(other: Byte): Double
    public operator fun minus(other: Short): Double
    public operator fun minus(other: Int): Double
    public operator fun minus(other: Long): Double
    public operator fun minus(other: Float): Double
    public operator fun minus(other: Double): Double
    public operator fun times(other: Byte): Double
    public operator fun times(other: Short): Double
    public operator fun times(other: Int): Double
    public operator fun times(other: Long): Double
    public operator fun times(other: Float): Double
    public operator fun times(other: Double): Double
    public operator fun div(other: Byte): Double
    public operator fun div(other: Short): Double
    public operator fun div(other: Int): Double
    public operator fun div(other: Long): Double
    public operator fun div(other: Float): Double
    public operator fun div(other: Double): Double
    public operator fun rem(other: Byte): Double
    public operator fun rem(other: Short): Double
    public operator fun rem(other: Int): Double
    public operator fun rem(other: Long): Double
    public operator fun rem(other: Float): Double
    public operator fun rem(other: Double): Double
    public operator fun inc(): Double
    public operator fun dec(): Double
    public operator fun unaryPlus(): Double
    public operator fun unaryMinus(): Double
    public override fun toByte(): Byte
    public override fun toShort(): Short
    public override fun toInt(): Int
    public override fun toLong(): Long
    public override fun toFloat(): Float
    public override fun toDouble(): Double
    public fun toChar(): Char
    public override fun equals(other: Any?): Boolean
    public override fun hashCode(): Int
    public override fun toString(): String
}

