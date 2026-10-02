// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin

public class Array<T> {
    public constructor(size: Int, init: (Int) -> T)
    public operator fun get(index: Int): T
    public operator fun set(index: Int, value: T): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.Iterator<T>
}

public class ByteArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Byte)
    public operator fun get(index: Int): Byte
    public operator fun set(index: Int, value: Byte): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.ByteIterator
}

public class ShortArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Short)
    public operator fun get(index: Int): Short
    public operator fun set(index: Int, value: Short): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.ShortIterator
}

public class IntArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Int)
    public operator fun get(index: Int): Int
    public operator fun set(index: Int, value: Int): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.IntIterator
}

public class LongArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Long)
    public operator fun get(index: Int): Long
    public operator fun set(index: Int, value: Long): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.LongIterator
}

public class FloatArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Float)
    public operator fun get(index: Int): Float
    public operator fun set(index: Int, value: Float): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.FloatIterator
}

public class DoubleArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Double)
    public operator fun get(index: Int): Double
    public operator fun set(index: Int, value: Double): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.DoubleIterator
}

public class CharArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Char)
    public operator fun get(index: Int): Char
    public operator fun set(index: Int, value: Char): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.CharIterator
}

public class BooleanArray {
    public constructor(size: Int)
    public constructor(size: Int, init: (Int) -> Boolean)
    public operator fun get(index: Int): Boolean
    public operator fun set(index: Int, value: Boolean): Unit
    public val size: Int
    public operator fun iterator(): kotlin.collections.BooleanIterator
}

