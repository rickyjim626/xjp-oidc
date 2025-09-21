//! Cache abstraction for JWKS and discovery metadata

use std::time::{Duration, Instant};

/// Cache trait for storing and retrieving values with TTL
pub trait Cache<K, V>: Send + Sync {
    /// Get a value from the cache
    fn get(&self, key: &K) -> Option<V>;

    /// Put a value into the cache with TTL in seconds
    fn put(&self, key: K, value: V, ttl_secs: u64);

    /// Remove a value from the cache
    fn remove(&self, key: &K) -> Option<V>;

    /// Clear all values from the cache
    fn clear(&self);
}

/// No-op cache implementation (always returns None)
#[derive(Clone)]
pub struct NoOpCache;

impl<K, V> Cache<K, V> for NoOpCache {
    fn get(&self, _key: &K) -> Option<V> {
        None
    }

    fn put(&self, _key: K, _value: V, _ttl_secs: u64) {}

    fn remove(&self, _key: &K) -> Option<V> {
        None
    }

    fn clear(&self) {}
}

/// Simple LRU cache implementation
#[cfg(feature = "lru")]
pub struct LruCacheImpl<K: std::hash::Hash + Eq + Clone, V: Clone> {
    inner: std::sync::Mutex<LruCacheInner<K, V>>,
}

#[cfg(feature = "lru")]
struct LruCacheInner<K: std::hash::Hash + Eq + Clone, V: Clone> {
    cache: lru::LruCache<K, (V, Instant)>,
}

#[cfg(feature = "lru")]
impl<K: std::hash::Hash + Eq + Clone, V: Clone> LruCacheImpl<K, V> {
    /// Create a new LRU cache with the specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(LruCacheInner {
                cache: lru::LruCache::new(capacity.try_into().unwrap()),
            }),
        }
    }
}

#[cfg(feature = "lru")]
impl<K: std::hash::Hash + Eq + Clone + Send + Sync + std::fmt::Display, V: Clone + Send + Sync>
    Cache<K, V> for LruCacheImpl<K, V>
{
    fn get(&self, key: &K) -> Option<V> {
        let mut inner = self.inner.lock().unwrap();
        let result = if let Some((value, expires_at)) = inner.cache.get(key) {
            if Instant::now() < *expires_at {
                Some(value.clone())
            } else {
                inner.cache.pop(key);
                None
            }
        } else {
            None
        };

        tracing::debug!(
            target: "xjp_oidc::cache",
            cache_key = %key,
            cache_hit = result.is_some(),
            cache_type = "lru",
            "缓存查询"
        );

        result
    }

    fn put(&self, key: K, value: V, ttl_secs: u64) {
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs);
        let mut inner = self.inner.lock().unwrap();
        inner.cache.put(key, (value, expires_at));
    }

    fn remove(&self, key: &K) -> Option<V> {
        let mut inner = self.inner.lock().unwrap();
        inner.cache.pop(key).map(|(v, _)| v)
    }

    fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cache.clear();
    }
}

/// Moka-based async cache implementation
#[cfg(all(not(target_arch = "wasm32"), feature = "moka"))]
#[derive(Clone)]
pub struct MokaCacheImpl<K: std::hash::Hash + Eq + Clone + Send + Sync, V: Clone + Send + Sync> {
    cache: moka::future::Cache<K, V>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "moka"))]
impl<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static, V: Clone + Send + Sync + 'static>
    MokaCacheImpl<K, V>
{
    /// Create a new Moka cache with the specified capacity
    pub fn new(capacity: u64) -> Self {
        let cache = moka::future::Cache::builder().max_capacity(capacity).build();
        Self { cache }
    }

    /// Create a new Moka cache with custom configuration
    pub fn with_config(
        capacity: u64,
        time_to_live: Option<Duration>,
        time_to_idle: Option<Duration>,
    ) -> Self {
        let mut builder = moka::future::Cache::builder().max_capacity(capacity);

        if let Some(ttl) = time_to_live {
            builder = builder.time_to_live(ttl);
        }

        if let Some(tti) = time_to_idle {
            builder = builder.time_to_idle(tti);
        }

        Self { cache: builder.build() }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "moka"))]
impl<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static, V: Clone + Send + Sync + 'static>
    Cache<K, V> for MokaCacheImpl<K, V>
{
    fn get(&self, key: &K) -> Option<V> {
        // Note: This blocks on async operation, which is not ideal
        // Consider making Cache trait async in future versions
        futures::executor::block_on(async { self.cache.get(key).await })
    }

    fn put(&self, key: K, value: V, ttl_secs: u64) {
        // Note: This blocks on async operation, which is not ideal
        // Consider making Cache trait async in future versions
        futures::executor::block_on(async {
            // TODO: Moka 0.12 doesn't support per-entry TTL directly.
            // The TTL must be configured at cache creation time.
            // For now, we ignore the ttl_secs parameter for individual entries.
            // Consider upgrading to a newer version or using a different approach.
            if ttl_secs > 0 {
                // Log warning or consider alternative implementation
                // For now, just insert with the cache's global TTL settings
                self.cache.insert(key, value).await;
            } else {
                // No TTL specified, use default cache behavior
                self.cache.insert(key, value).await;
            }
        });
    }

    fn remove(&self, key: &K) -> Option<V> {
        futures::executor::block_on(async { self.cache.remove(key).await })
    }

    fn clear(&self) {
        self.cache.invalidate_all();
    }
}
