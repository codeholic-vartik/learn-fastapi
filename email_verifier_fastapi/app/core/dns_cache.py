from functools import wraps
from cachetools import TTLCache
from typing import Dict, Any, Optional, List, Union
import dns.resolver
import dns.exception
import time
import logging
from threading import Lock, Thread
from app.core.config import DNS_CONFIG

class DNSCache:
    """DNS caching utility with enhanced error handling and monitoring"""

    def __init__(self, ttl: int = DNS_CONFIG['CACHE_TTL'], maxsize: int = DNS_CONFIG['CACHE_MAXSIZE']):
        """
        Initialize DNS cache

        Args:
            ttl: Time to live for cache entries in seconds
            maxsize: Maximum number of entries in cache
        """
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._lock = Lock()
        self.resolver = dns.resolver.Resolver()
        self._start_cleanup_task()

        # Configure resolver from settings
        self.resolver.nameservers = DNS_CONFIG['NAMESERVERS']
        self.resolver.timeout = DNS_CONFIG['TIMEOUT']
        self.resolver.lifetime = DNS_CONFIG['LIFETIME']

        # Initialize logging
        self.logger = logging.getLogger('dns_cache')

        # Statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'errors': 0,
            'last_error': None,
            'last_error_time': None
        }

    def _start_cleanup_task(self):
        """Start a background task to clean up expired cache entries."""
        def cleanup():
            while True:
                time.sleep(self._cache.ttl // 2)  # Cleanup every half TTL
                with self._lock:
                    self._cache.expire()
        Thread(target=cleanup, daemon=True).start()

    def _cache_key(self, domain: str, record_type: str) -> str:
        """
        Generate cache key from domain and record type

        Args:
            domain: Domain name
            record_type: DNS record type

        Returns:
            str: Cache key
        """
        return f"{domain.lower()}:{record_type.upper()}"

    def lookup(self, domain: str, record_type: str = 'MX') -> Optional[Dict[str, Any]]:
        """
        Perform a cached DNS lookup with retry logic

        Args:
            domain: Domain name to lookup
            record_type: DNS record type

        Returns:
            Dict containing lookup results or None if lookup fails
        """
        cache_key = self._cache_key(domain, record_type)

        # Try to get from cache first
        with self._lock:
            if cache_key in self._cache:
                self._stats['hits'] += 1
                return self._cache[cache_key]
            self._stats['misses'] += 1

        # Not in cache, perform lookup with retries
        result = self._perform_lookup_with_retries(domain, record_type, cache_key)
        return result

    def _perform_lookup_with_retries(self, domain: str, record_type: str, cache_key: str) -> Optional[Dict[str, Any]]:
        """Perform DNS lookup with retry logic and cache the result."""
        for attempt in range(DNS_CONFIG['RETRY_COUNT']):
            try:
                start_time = time.time()
                records = self.resolver.resolve(domain, record_type)
                lookup_time = time.time() - start_time

                result = self._format_result(records, record_type, lookup_time)

                # Cache the successful result
                with self._lock:
                    self._cache[cache_key] = result
                return result

            except dns.resolver.NXDOMAIN:
                return self._handle_error('NXDOMAIN', domain, cache_key, start_time)
            except dns.resolver.NoAnswer:
                return self._handle_error('NoAnswer', domain, cache_key, start_time)
            except dns.resolver.Timeout:
                if attempt < DNS_CONFIG['RETRY_COUNT'] - 1:
                    time.sleep(DNS_CONFIG['RETRY_TIMEOUT'])
                    continue
                return self._handle_error('Timeout', domain, cache_key, start_time)
            except Exception as e:
                if attempt < DNS_CONFIG['RETRY_COUNT'] - 1:
                    time.sleep(DNS_CONFIG['RETRY_TIMEOUT'])
                    continue
                return self._handle_error(str(e), domain, cache_key, start_time)

        return None

    def _format_result(self, records, record_type: str, lookup_time: float) -> Dict[str, Any]:
        """Format DNS lookup results based on record type."""
        if record_type == 'MX':
            result = {
                'records': [
                    {
                        'exchange': str(r.exchange).rstrip('.'),
                        'preference': r.preference
                    } for r in records
                ],
                'lookup_time': lookup_time,
                'timestamp': time.time()
            }
        elif record_type == 'TXT':
            result = {
                'records': [r.strings[0].decode() for r in records],
                'lookup_time': lookup_time,
                'timestamp': time.time()
            }
        else:
            result = {
                'records': [str(r) for r in records],
                'lookup_time': lookup_time,
                'timestamp': time.time()
            }
        return result

    def _handle_error(self, error: str, domain: str, cache_key: str, start_time: float) -> Dict[str, Any]:
        """Handle DNS lookup errors and update statistics."""
        result = {
            'error': error,
            'lookup_time': time.time() - start_time
        }
        with self._lock:
            self._cache[cache_key] = result
        self._update_error_stats(error, domain)
        return result

    def _update_error_stats(self, error: str, domain: str) -> None:
        """Update error statistics."""
        with self._lock:
            self._stats['errors'] += 1
            self._stats['last_error'] = f"{error} ({domain})"
            self._stats['last_error_time'] = time.time()
        self.logger.error(f"DNS lookup error for {domain}: {error}")

    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
            self.logger.info("DNS cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics and health metrics

        Returns:
            Dict containing cache statistics and health information
        """
        with self._lock:
            stats = {
                'size': len(self._cache),
                'maxsize': self._cache.maxsize,
                'ttl': self._cache.ttl,
                'currsize': len(self._cache),
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'hit_ratio': (self._stats['hits'] / (self._stats['hits'] + self._stats['misses'])
                             if (self._stats['hits'] + self._stats['misses']) > 0 else 0),
                'errors': self._stats['errors'],
                'last_error': self._stats['last_error'],
                'last_error_time': self._stats['last_error_time'],
                'nameservers': self.resolver.nameservers,
                'timeout': self.resolver.timeout,
                'lifetime': self.resolver.lifetime
            }
            return stats

    def bulk_lookup(self, domains: List[str], record_type: str = 'MX') -> Dict[str, Any]:
        """
        Perform bulk DNS lookups efficiently

        Args:
            domains: List of domain names to lookup
            record_type: DNS record type

        Returns:
            Dict containing results for each domain
        """
        return {domain: self.lookup(domain, record_type) for domain in domains}

    def prefetch(self, domain: str, record_types: List[str] = ['MX', 'TXT', 'A']) -> None:
        """
        Prefetch DNS records for a domain

        Args:
            domain: Domain name to prefetch
            record_types: List of record types to prefetch
        """
        for record_type in record_types:
            self.lookup(domain, record_type)

    def is_valid_domain(self, domain: str) -> bool:
        """
        Check if a domain exists and has valid DNS records

        Args:
            domain: Domain name to check

        Returns:
            bool: Whether domain is valid
        """
        result = self.lookup(domain, 'A')
        return result is not None and 'error' not in result

    def get_mx_servers(self, domain: str) -> List[Dict[str, Union[str, int]]]:
        """
        Get sorted list of MX servers for a domain

        Args:
            domain: Domain name to lookup

        Returns:
            List of dicts containing MX server information
        """
        result = self.lookup(domain, 'MX')
        if not result or 'error' in result:
            return []
        return sorted(result.get('records', []), key=lambda x: x['preference'])

# Global DNS cache instance
dns_cache = DNSCache()

def cached_dns_lookup(func):
    """
    Decorator to add DNS caching to methods that perform DNS lookups
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not hasattr(self, 'dns_cache'):
            self.dns_cache = DNSCache()
        return func(self, *args, **kwargs)
    return wrapper