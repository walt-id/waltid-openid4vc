package id.walt.oid4vc.providers

interface SessionCacheInterface<T> {
  fun get(key: String): T?
  fun put(key: String, session: T): T
  fun remove(key: String): Boolean
}