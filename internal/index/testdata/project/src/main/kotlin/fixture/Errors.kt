package fixture

// Each error below is deliberate and its kotlinc diagnostic is asserted by the
// test suite. Keep the line numbers stable: tests refer to them.

fun unresolvedReference(): Int = MissingSymbol.value

fun typeMismatch(): String = 1

class Reassignment {
    fun run(): Int {
        val fixed = 1
        fixed = 2
        return fixed
    }
}

fun unresolvedCall(): Int = missingFunction(1, 2)

class MoreReassignment {
    val member: Int = 1

    fun run(): Int {
        member = 2
        return member
    }
}

interface NeedsArea {
    fun area(): Int
    fun label(): String = "shape"
}
class Unimplemented : NeedsArea

open class Parent { open fun greet() {} }
class Child : Parent() {
    override fun greet() {}
    override fun nothingHere() {}
}

fun initMismatch() { val s: String = 1 }
fun assignMismatch() { var s: String = ""; s = 1 }
fun returnMismatch(): String = 1
fun blockReturnMismatch(): String { return 1 }
fun takesInt(x: Int, y: String = "") = x
fun argMismatch() = takesInt("s")
fun missingArg() = takesInt()
fun noInit() { val q }
fun noBody(): Int
class Holder { val h: Int }

class Twice
class Twice
fun twice() = 1
fun twice() = 2
val twiceValue = 1
val twiceValue = 2

open class OpenBase {
    open fun greetAll() {}
    fun sealedGreet() {}
}
class FinalBase
class NoInit : OpenBase
class ExtendsFinal : FinalBase()
class Hides : OpenBase() { fun greetAll() {} }
class OverridesFinal : OpenBase() { override fun sealedGreet() {} }
class NoBodyMember { fun h() }
class AbstractInConcrete { abstract fun h() }
class UntypedProperty { val v }
class LateInits {
    lateinit var a: Int
    lateinit var b: String?
    lateinit var c: String = "x"
    lateinit val d: String
}
fun noReturn(): Int { val x = 1 }
fun bareReturn(): Int { return }
fun unitReturnsValue() { return 1 }
fun unsafe(s: String?) = s.length
fun ifExpression(c: Boolean) { val x = if (c) 1 }
fun ifBody(c: Boolean): Int = if (c) 1
abstract class Abstract { abstract fun a() }
enum class Colour { RED }
interface Plain
fun instantiate() { Abstract(); Colour(); Plain() }
fun nullToNonNull() { val s: String = null }
fun nullReturned(): String { return null }
fun condition(x: Int) { if (x) {} }
fun breakOutside() { break }
class TwoCompanions {
    companion object A
    companion object B
}
data class NoParams
data class NotProperty(x: Int)
class Sibling { val hidden = 1 }
class UsesSibling { fun f() = hidden }
abstract class AbstractBase
class NoInitAbstract : AbstractBase
