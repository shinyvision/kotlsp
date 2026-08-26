package fixture

import other.Reachable

/** The same type, correctly imported. Nothing may be reported here. */
fun importedProperly(value: Reachable): Int = value.id
