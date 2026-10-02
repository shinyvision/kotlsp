package e2e.kt

data class Item(val id: Int, val name: String?)

class Store(private val items: MutableList<Item>) {
    fun add(item: Item): Int {
        items.add(item)
        return items.size
    }

    fun names(): List<String> = items.map { item ->
        item.name ?: "none"
    }

    companion object {
        fun create(): Store = Store(mutableListOf())
    }
}

fun Int.doubled(): Int = this * 2

fun classify(n: Int): String = when {
    n < 0 -> "negative"
    n == 0 -> "zero"
    else -> "positive"
}

fun main() {
    val store = Store.create()
    store.add(Item(1, "a"))
    store.add(Item(2, null))
    val names = store.names()
    val total = names.size.doubled()
    val action: (Int) -> Int = { x ->
        x + total
    }
    val result = action(5)
    val label = classify(result)
    val upper = names.filter { it.isNotEmpty() }.let { list ->
        list.joinToString()
    }
    println("$label $result $upper")
}
