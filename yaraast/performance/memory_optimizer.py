"""Memory optimization utilities for processing large YARA rule collections."""

import gc
import sys
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Set

from yaraast.ast.base import ASTNode, YaraFile


@dataclass
class MemoryStats:
    """Memory usage statistics."""

    total_objects: int = 0
    ast_objects: int = 0
    memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    gc_collections: int = 0


class MemoryOptimizer:
    """Memory optimization utilities for large-scale AST processing.

    This class provides tools to minimize memory usage when processing
    huge YARA rule collections by implementing:
    - Weak reference tracking
    - Automatic garbage collection
    - Memory-efficient iteration
    - AST object pooling
    """

    def __init__(self,
                 memory_limit_mb: int = 1000,
                 gc_threshold: int = 1000,
                 enable_tracking: bool = True):
        """Initialize memory optimizer.

        Args:
            memory_limit_mb: Memory limit in MB before triggering aggressive cleanup
            gc_threshold: Number of objects before triggering garbage collection
            enable_tracking: Enable object tracking for memory analysis
        """
        self.memory_limit_mb = memory_limit_mb
        self.gc_threshold = gc_threshold
        self.enable_tracking = enable_tracking

        # Tracking
        self._tracked_objects: Set[weakref.ref] = set()
        self._stats = MemoryStats()
        self._object_counter = 0

        # AST object pool for reuse
        self._ast_pool: List[YaraFile] = []
        self._pool_size_limit = 100

    @contextmanager
    def memory_managed_context(self):
        """Context manager for memory-managed processing."""
        initial_memory = self._get_memory_usage()

        try:
            yield self
        finally:
            # Cleanup and report
            self.cleanup()
            final_memory = self._get_memory_usage()

            memory_diff = final_memory - initial_memory
            if memory_diff > 0:
                print(f"Memory usage increased by {memory_diff:.1f} MB during processing")

    def track_object(self, obj: Any) -> None:
        """Track an object for memory monitoring."""
        if not self.enable_tracking:
            return

        try:
            ref = weakref.ref(obj, self._object_cleanup_callback)
            self._tracked_objects.add(ref)
            self._object_counter += 1

            # Periodic garbage collection
            if self._object_counter % self.gc_threshold == 0:
                self.force_cleanup()

        except TypeError:
            # Object doesn't support weak references
            pass

    def create_memory_efficient_ast(self) -> YaraFile:
        """Create or reuse an AST object from the pool."""
        if self._ast_pool:
            ast = self._ast_pool.pop()
            # Reset the AST
            ast.imports.clear()
            ast.includes.clear()
            ast.rules.clear()
            return ast
        else:
            ast = YaraFile(imports=[], includes=[], rules=[])
            self.track_object(ast)
            return ast

    def return_ast_to_pool(self, ast: YaraFile) -> None:
        """Return an AST object to the pool for reuse."""
        if len(self._ast_pool) < self._pool_size_limit:
            # Clear references to allow garbage collection of contained objects
            ast.imports.clear()
            ast.includes.clear()
            ast.rules.clear()
            self._ast_pool.append(ast)

    def memory_efficient_iterator(self,
                                 items: List[Any],
                                 batch_size: int = 10) -> Iterator[List[Any]]:
        """Create memory-efficient iterator that processes items in batches."""
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            yield batch

            # Check memory usage after each batch
            if i % (batch_size * 5) == 0:  # Check every 5 batches
                current_memory = self._get_memory_usage()
                if current_memory > self.memory_limit_mb:
                    self.force_cleanup()

    def minimize_ast_memory(self, ast: YaraFile) -> YaraFile:
        """Minimize memory usage of an AST by removing unnecessary data."""
        # Create a minimal copy with only essential information
        minimal_ast = YaraFile(imports=[], includes=[], rules=[])

        # Copy only essential parts
        for imp in ast.imports:
            minimal_ast.imports.append(imp)

        for rule in ast.rules:
            # Create minimal rule copy
            minimal_rule = type(rule)(
                name=rule.name,
                modifiers=rule.modifiers.copy() if rule.modifiers else [],
                tags=rule.tags.copy() if rule.tags else [],
                meta=rule.meta.copy() if rule.meta else {},
                strings=rule.strings.copy() if rule.strings else [],
                condition=rule.condition
            )
            minimal_ast.rules.append(minimal_rule)

        self.track_object(minimal_ast)
        return minimal_ast

    def batch_process_with_memory_limit(self,
                                       items: List[Any],
                                       processor_func: Callable[[Any], Any],
                                       batch_size: int = 50) -> Iterator[Any]:
        """Process items in batches with memory management."""
        processed_count = 0

        for batch in self.memory_efficient_iterator(items, batch_size):
            batch_results = []

            for item in batch:
                try:
                    result = processor_func(item)
                    batch_results.append(result)
                    processed_count += 1

                    # Track memory usage
                    if hasattr(result, '__dict__'):
                        self.track_object(result)

                except Exception as e:
                    # Log error but continue processing
                    batch_results.append(f"Error processing item: {e}")

            yield batch_results

            # Memory check after each batch
            current_memory = self._get_memory_usage()
            if current_memory > self.memory_limit_mb:
                self.force_cleanup()

    def get_memory_stats(self) -> MemoryStats:
        """Get current memory statistics."""
        self._stats.total_objects = len(self._tracked_objects)
        self._stats.ast_objects = len([ref for ref in self._tracked_objects
                                     if ref() and isinstance(ref(), YaraFile)])
        self._stats.memory_mb = self._get_memory_usage()

        return self._stats

    def force_cleanup(self) -> int:
        """Force garbage collection and cleanup of tracked objects."""
        # Remove dead references
        dead_refs = {ref for ref in self._tracked_objects if ref() is None}
        self._tracked_objects -= dead_refs

        # Force garbage collection
        collected = gc.collect()
        self._stats.gc_collections += 1

        # Update memory stats
        current_memory = self._get_memory_usage()
        self._stats.peak_memory_mb = max(self._stats.peak_memory_mb, current_memory)

        return collected

    def cleanup(self) -> None:
        """Comprehensive cleanup of all tracked resources."""
        # Clear AST pool
        self._ast_pool.clear()

        # Clear tracked objects
        self._tracked_objects.clear()

        # Force garbage collection
        self.force_cleanup()

    def optimize_for_large_collection(self, collection_size: int) -> Dict[str, Any]:
        """Optimize settings based on collection size."""
        recommendations = {
            'batch_size': min(50, max(10, collection_size // 100)),
            'gc_threshold': min(1000, max(100, collection_size // 10)),
            'memory_limit_mb': max(500, min(2000, collection_size // 100)),
            'enable_pooling': collection_size > 100,
            'use_streaming': collection_size > 500
        }

        # Apply recommendations
        if recommendations['enable_pooling']:
            self._pool_size_limit = min(200, collection_size // 50)

        self.gc_threshold = recommendations['gc_threshold']
        self.memory_limit_mb = recommendations['memory_limit_mb']

        return recommendations

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import os

            import psutil

            process = psutil.Process(os.getpid())
            memory_bytes = process.memory_info().rss
            return memory_bytes / (1024 * 1024)

        except ImportError:
            # Fallback to sys.getsizeof for rough estimate
            return sys.getsizeof(self._tracked_objects) / (1024 * 1024)

    def _object_cleanup_callback(self, ref: weakref.ref) -> None:
        """Callback when tracked object is garbage collected."""
        self._tracked_objects.discard(ref)


class LazyASTLoader:
    """Lazy loader for AST objects to minimize memory usage."""

    def __init__(self, optimizer: Optional[MemoryOptimizer] = None):
        """Initialize lazy loader.

        Args:
            optimizer: Memory optimizer instance to use
        """
        self.optimizer = optimizer or MemoryOptimizer()
        self._cache: Dict[str, weakref.ref] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def load_ast(self, identifier: str, loader_func: Callable[[], YaraFile]) -> YaraFile:
        """Load AST with caching and memory optimization.

        Args:
            identifier: Unique identifier for the AST
            loader_func: Function that loads/creates the AST

        Returns:
            The loaded AST
        """
        # Check cache first
        if identifier in self._cache:
            cached_ref = self._cache[identifier]
            cached_ast = cached_ref()

            if cached_ast is not None:
                self._cache_hits += 1
                return cached_ast
            else:
                # Dead reference, remove from cache
                del self._cache[identifier]

        # Load AST
        self._cache_misses += 1
        ast = loader_func()

        # Track and cache
        if self.optimizer:
            self.optimizer.track_object(ast)

        self._cache[identifier] = weakref.ref(ast)

        return ast

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self._cache_hits + self._cache_misses
        hit_rate = (self._cache_hits / total_requests * 100) if total_requests > 0 else 0

        return {
            'cache_hits': self._cache_hits,
            'cache_misses': self._cache_misses,
            'hit_rate_percent': hit_rate,
            'cached_objects': len(self._cache),
            'live_objects': len([ref for ref in self._cache.values() if ref() is not None])
        }

    def clear_cache(self) -> None:
        """Clear the AST cache."""
        self._cache.clear()


class MemoryEfficientProcessor:
    """Memory-efficient processor for large AST collections."""

    def __init__(self, memory_limit_mb: int = 1000):
        """Initialize memory-efficient processor.

        Args:
            memory_limit_mb: Memory limit in MB
        """
        self.optimizer = MemoryOptimizer(memory_limit_mb=memory_limit_mb)
        self.loader = LazyASTLoader(self.optimizer)

    def process_collection(self,
                          items: List[Any],
                          processor_func: Callable[[Any], Any],
                          batch_size: Optional[int] = None) -> Iterator[Any]:
        """Process a collection with automatic memory management.

        Args:
            items: Items to process
            processor_func: Function to process each item
            batch_size: Batch size (auto-calculated if None)

        Yields:
            Processed results
        """
        # Optimize settings based on collection size
        if batch_size is None:
            settings = self.optimizer.optimize_for_large_collection(len(items))
            batch_size = settings['batch_size']

        with self.optimizer.memory_managed_context():
            yield from self.optimizer.batch_process_with_memory_limit(
                items, processor_func, batch_size
            )

    def get_processing_stats(self) -> Dict[str, Any]:
        """Get comprehensive processing statistics."""
        memory_stats = self.optimizer.get_memory_stats()
        cache_stats = self.loader.get_cache_stats()

        return {
            'memory': {
                'current_mb': memory_stats.memory_mb,
                'peak_mb': memory_stats.peak_memory_mb,
                'tracked_objects': memory_stats.total_objects,
                'ast_objects': memory_stats.ast_objects,
                'gc_collections': memory_stats.gc_collections
            },
            'cache': cache_stats
        }
