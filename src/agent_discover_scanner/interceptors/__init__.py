"""
Enterprise network interceptor detection.

detect_network_interceptors() auto-discovers all NetworkInterceptor subclasses
under the sse/ sub-package via importlib and runs them in order. Returns a list
of InterceptorResult for every proxy vendor that was found active.

When interceptors are detected, Layer 2 psutil.net_connections() sees the proxy
IP instead of bedrock-runtime.*.amazonaws.com. Use the fallback strategies in
each InterceptorResult to supplement Layer 2 detection.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from agent_discover_scanner.interceptors.base import InterceptorResult, NetworkInterceptor


def detect_network_interceptors() -> list[InterceptorResult]:
    """
    Auto-discover and run all SSE proxy interceptor plugins.

    Returns one InterceptorResult per vendor that is actively detected.
    Never raises — individual plugin failures are silently skipped.
    """
    results: list[InterceptorResult] = []

    try:
        import agent_discover_scanner.interceptors.sse as sse_pkg

        for _importer, modname, _ispkg in pkgutil.iter_modules(sse_pkg.__path__):
            try:
                mod = importlib.import_module(f"agent_discover_scanner.interceptors.sse.{modname}")
                for _name, obj in inspect.getmembers(mod, inspect.isclass):
                    if (
                        issubclass(obj, NetworkInterceptor)
                        and obj is not NetworkInterceptor
                        and obj.__module__ == mod.__name__
                    ):
                        try:
                            result = obj().detect()
                            if result is not None:
                                results.append(result)
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception:
        pass

    return results
