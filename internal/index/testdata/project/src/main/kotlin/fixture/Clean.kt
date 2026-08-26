package fixture

/** Compiles without a single complaint. Any diagnostic here is a false positive. */
class Clean(private val label: String) {
    fun greet(name: String): String = "$label $name"

    fun sum(values: List<Int>): Int = values.sum()

    fun guarded(other: Clean?): String {
        if (other == null || other.label.isEmpty()) {
            return label
        }
        return other.label
    }
}

annotation class Marker(
    val message: String = "",
    val tags: Array<String> = [],
)

// Near misses: each is one step from an error above and must stay silent.
val widened: Long = 1
val real: Double = 1.0
val single: Float = 1.0f
fun withDefault(x: Int = 1) = x
fun callsDefault() = withDefault()
fun named(a: Int, b: Int) = a + b
fun callsNamed() = named(b = 1, a = 2)
fun spread(vararg xs: Int) = xs.size
fun callsSpread() = spread()
fun blockOk(): String { return "x" }
var counter: Int = 0
fun bump() { counter = 1 }
interface WithDefault { fun f(): Int = 1 }
class UsesDefault : WithDefault
class Implements : WithDefault { override fun f() = 2 }
class Delegated(impl: WithDefault) : WithDefault by impl
abstract class AbstractHolder { abstract val a: Int }
class Lazily { val v: Int by lazy { 1 } }
class Accessor { val g: Int get() = 1 }
class Constructed(val c: Int)
class Late { lateinit var late: String }
class Stringly { override fun toString() = "c" }
open class OpenParent { open fun f() {} }
class InitialisedChild : OpenParent() { override fun f() {} }
class SecondaryInit : OpenParent { constructor() : super() }
interface Plainer
class ImplementsPlainer : Plainer
class Overloads : OpenParent() { fun f(x: Int) = x }
abstract class AbstractShape { abstract fun area(): Int }
fun anonymousShape() = object : AbstractShape() { override fun area() = 1 }
fun returns(): Int { return 1 }
fun throws(): Int { throw IllegalStateException() }
fun todo(): Int { TODO() }
fun loops(): Int { while (true) { } }
fun ifElse(c: Boolean) = if (c) 1 else 2
fun safe(s: String?) = s?.length
fun smart(s: String?): Int { if (s == null) return 0; return s.length }
fun nullableNull() { val s: String? = null }
fun boolCondition(b: Boolean) { if (b) {} }
fun breaks() { while (true) { break } }
class OneCompanion { companion object }
data class Proper(val x: Int)
class Lateinit { lateinit var s: String }
