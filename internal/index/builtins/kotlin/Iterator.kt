// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Signatures only; behaviour lives in the runtime.

package kotlin.collections

public interface Iterator<out T> {
    public operator fun next(): T
    public operator fun hasNext(): Boolean
}

public interface MutableIterator<out T> : Iterator<T> {
    public fun remove(): Unit
}

public interface ListIterator<out T> : Iterator<T> {
    override fun next(): T
    override fun hasNext(): Boolean
    public fun hasPrevious(): Boolean
    public fun previous(): T
    public fun nextIndex(): Int
    public fun previousIndex(): Int
}

public interface MutableListIterator<T> : ListIterator<T>, MutableIterator<T> {
    override fun next(): T
    override fun hasNext(): Boolean
    override fun remove(): Unit
    public fun set(element: T): Unit
    public fun add(element: T): Unit
}

public abstract class ByteIterator : Iterator<Byte> {
    public final override operator fun next(): Byte
    public abstract fun nextByte(): Byte
}

public abstract class ShortIterator : Iterator<Short> {
    public final override operator fun next(): Short
    public abstract fun nextShort(): Short
}

public abstract class IntIterator : Iterator<Int> {
    public final override operator fun next(): Int
    public abstract fun nextInt(): Int
}

public abstract class LongIterator : Iterator<Long> {
    public final override operator fun next(): Long
    public abstract fun nextLong(): Long
}

public abstract class FloatIterator : Iterator<Float> {
    public final override operator fun next(): Float
    public abstract fun nextFloat(): Float
}

public abstract class DoubleIterator : Iterator<Double> {
    public final override operator fun next(): Double
    public abstract fun nextDouble(): Double
}

public abstract class CharIterator : Iterator<Char> {
    public final override operator fun next(): Char
    public abstract fun nextChar(): Char
}

public abstract class BooleanIterator : Iterator<Boolean> {
    public final override operator fun next(): Boolean
    public abstract fun nextBoolean(): Boolean
}

