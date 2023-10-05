package id.walt.oid4vc.util

import java.util.*

actual fun randomUUID(): String {
    return UUID.randomUUID().toString()
}
