package fixture

// `Reachable` exists in this project but is not imported here, so it cannot be
// named. This is the shape of the most common real error: a forgotten import.
fun needsImport(value: Reachable): Int = value.id
