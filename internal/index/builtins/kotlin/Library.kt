// Declarations of the Kotlin language's built-in types. The Kotlin compiler
// carries these in .kotlin_builtins resources, so no class file declares them and
// a project without the stdlib sources jar would otherwise have no Any, Enum,
// String, List or Int. Compiler intrinsics with no class file: arrayOf, enumValues and friends.

package kotlin

public inline fun <reified T> arrayOf(vararg elements: T): Array<T>
public fun <T> arrayOfNulls(size: Int): Array<T?>
public fun byteArrayOf(vararg elements: Byte): ByteArray
public fun shortArrayOf(vararg elements: Short): ShortArray
public fun intArrayOf(vararg elements: Int): IntArray
public fun longArrayOf(vararg elements: Long): LongArray
public fun floatArrayOf(vararg elements: Float): FloatArray
public fun doubleArrayOf(vararg elements: Double): DoubleArray
public fun charArrayOf(vararg elements: Char): CharArray
public fun booleanArrayOf(vararg elements: Boolean): BooleanArray
public inline fun <reified T : Enum<T>> enumValues(): Array<T>
public inline fun <reified T : Enum<T>> enumValueOf(name: String): T
