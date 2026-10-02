// The JVM standard library's type aliases in package kotlin. They have no
// class file of their own -- the compiler reads them from the stdlib's
// metadata -- so without the stdlib sources jar nothing declared `Exception`
// or `Comparator` and every use read as unresolved.

package kotlin

public typealias Error = java.lang.Error
public typealias Exception = java.lang.Exception
public typealias RuntimeException = java.lang.RuntimeException
public typealias IllegalArgumentException = java.lang.IllegalArgumentException
public typealias IllegalStateException = java.lang.IllegalStateException
public typealias IndexOutOfBoundsException = java.lang.IndexOutOfBoundsException
public typealias UnsupportedOperationException = java.lang.UnsupportedOperationException
public typealias ArithmeticException = java.lang.ArithmeticException
public typealias NumberFormatException = java.lang.NumberFormatException
public typealias NullPointerException = java.lang.NullPointerException
public typealias ClassCastException = java.lang.ClassCastException
public typealias AssertionError = java.lang.AssertionError
public typealias NoSuchElementException = java.util.NoSuchElementException
public typealias ConcurrentModificationException = java.util.ConcurrentModificationException
public typealias Comparator<T> = java.util.Comparator<T>
public typealias Throws = kotlin.jvm.Throws
