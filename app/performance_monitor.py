"""
Performance Monitoring System for Open Omne Node
Tracks metrics, performance, and health status of the node.
"""

import time
import threading
import logging
import psutil
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict


@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: float
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_connections: int
    consensus_rounds: int
    blocks_processed: int
    transactions_processed: int
    errors_count: int
    response_time_avg: float


class MetricsCollector:
    """Collects system and application metrics"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._metrics_history = deque(maxlen=1000)  # Keep last 1000 measurements
        self._counters = defaultdict(int)
        self._timers = {}
        self._response_times = deque(maxlen=100)  # Keep last 100 response times
        self._lock = threading.RLock()
    
    def collect_system_metrics(self) -> Dict[str, float]:
        """Collect system performance metrics"""
        try:
            # CPU usage
            cpu_usage = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage = disk.percent
            
            # Network connections
            connections = len(psutil.net_connections())
            
            return {
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'disk_usage': disk_usage,
                'network_connections': connections
            }
        except Exception as e:
            self.logger.warning(f"Failed to collect system metrics: {e}")
            return {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'network_connections': 0
            }
    
    def increment_counter(self, name: str, value: int = 1):
        """Increment a counter metric"""
        with self._lock:
            self._counters[name] += value
    
    def record_response_time(self, response_time: float):
        """Record a response time measurement"""
        with self._lock:
            self._response_times.append(response_time)
    
    def start_timer(self, name: str):
        """Start a timer"""
        with self._lock:
            self._timers[name] = time.time()
    
    def stop_timer(self, name: str) -> float:
        """Stop a timer and return elapsed time"""
        with self._lock:
            if name in self._timers:
                elapsed = time.time() - self._timers[name]
                del self._timers[name]
                return elapsed
            return 0.0
    
    def get_counter(self, name: str) -> int:
        """Get counter value"""
        with self._lock:
            return self._counters.get(name, 0)
    
    def get_average_response_time(self) -> float:
        """Get average response time"""
        with self._lock:
            if not self._response_times:
                return 0.0
            return sum(self._response_times) / len(self._response_times)
    
    def collect_metrics(self) -> PerformanceMetrics:
        """Collect all metrics and return as PerformanceMetrics object"""
        system_metrics = self.collect_system_metrics()
        
        with self._lock:
            metrics = PerformanceMetrics(
                timestamp=time.time(),
                cpu_usage=system_metrics['cpu_usage'],
                memory_usage=system_metrics['memory_usage'],
                disk_usage=system_metrics['disk_usage'],
                network_connections=system_metrics['network_connections'],
                consensus_rounds=self._counters.get('consensus_rounds', 0),
                blocks_processed=self._counters.get('blocks_processed', 0),
                transactions_processed=self._counters.get('transactions_processed', 0),
                errors_count=self._counters.get('errors', 0),
                response_time_avg=self.get_average_response_time()
            )
            
            self._metrics_history.append(metrics)
            return metrics
    
    def get_metrics_history(self, duration_minutes: int = 60) -> List[PerformanceMetrics]:
        """Get metrics history for the specified duration"""
        cutoff_time = time.time() - (duration_minutes * 60)
        
        with self._lock:
            return [m for m in self._metrics_history if m.timestamp >= cutoff_time]
    
    def reset_counters(self):
        """Reset all counters"""
        with self._lock:
            self._counters.clear()
            self._response_times.clear()


class HealthChecker:
    """Health checking system"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.logger = logging.getLogger(__name__)
        self._health_checks = {}
        self._health_status = {}
    
    def register_health_check(self, name: str, check_function, critical: bool = False):
        """Register a health check function"""
        self._health_checks[name] = {
            'function': check_function,
            'critical': critical
        }
    
    def run_health_checks(self) -> Dict[str, Any]:
        """Run all registered health checks"""
        results = {}
        overall_healthy = True
        
        for name, check_info in self._health_checks.items():
            try:
                result = check_info['function']()
                is_healthy = result.get('healthy', False) if isinstance(result, dict) else bool(result)
                
                results[name] = {
                    'healthy': is_healthy,
                    'details': result if isinstance(result, dict) else {'status': result},
                    'critical': check_info['critical'],
                    'timestamp': time.time()
                }
                
                if check_info['critical'] and not is_healthy:
                    overall_healthy = False
                    
            except Exception as e:
                self.logger.error(f"Health check '{name}' failed: {e}")
                results[name] = {
                    'healthy': False,
                    'details': {'error': str(e)},
                    'critical': check_info['critical'],
                    'timestamp': time.time()
                }
                
                if check_info['critical']:
                    overall_healthy = False
        
        self._health_status = {
            'overall_healthy': overall_healthy,
            'checks': results,
            'timestamp': time.time()
        }
        
        return self._health_status
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        return self._health_status.copy() if self._health_status else {'overall_healthy': False}


class PerformanceMonitor:
    """Main performance monitoring system"""
    
    def __init__(self, collection_interval: int = 60):
        self.collection_interval = collection_interval
        self.metrics_collector = MetricsCollector()
        self.health_checker = HealthChecker(self.metrics_collector)
        self.logger = logging.getLogger(__name__)
        
        self._monitoring_thread = None
        self._running = False
        self._alerts = deque(maxlen=100)
        
        # Register default health checks
        self._register_default_health_checks()
    
    def _register_default_health_checks(self):
        """Register default health checks"""
        
        def cpu_check():
            metrics = self.metrics_collector.collect_system_metrics()
            cpu_usage = metrics.get('cpu_usage', 0)
            return {
                'healthy': cpu_usage < 90,
                'cpu_usage': cpu_usage,
                'threshold': 90
            }
        
        def memory_check():
            metrics = self.metrics_collector.collect_system_metrics()
            memory_usage = metrics.get('memory_usage', 0)
            return {
                'healthy': memory_usage < 90,
                'memory_usage': memory_usage,
                'threshold': 90
            }
        
        def disk_check():
            metrics = self.metrics_collector.collect_system_metrics()
            disk_usage = metrics.get('disk_usage', 0)
            return {
                'healthy': disk_usage < 95,
                'disk_usage': disk_usage,
                'threshold': 95
            }
        
        self.health_checker.register_health_check('cpu', cpu_check, critical=True)
        self.health_checker.register_health_check('memory', memory_check, critical=True)
        self.health_checker.register_health_check('disk', disk_check, critical=True)
    
    def start_monitoring(self):
        """Start the monitoring system"""
        if self._running:
            return
        
        self._running = True
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitoring_thread.start()
        self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop the monitoring system"""
        self._running = False
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        self.logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # Collect metrics
                metrics = self.metrics_collector.collect_metrics()
                
                # Run health checks
                health_status = self.health_checker.run_health_checks()
                
                # Check for alerts
                self._check_alerts(metrics, health_status)
                
                # Log metrics periodically
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    self._log_metrics(metrics)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
            
            time.sleep(self.collection_interval)
    
    def _check_alerts(self, metrics: PerformanceMetrics, health_status: Dict[str, Any]):
        """Check for alert conditions"""
        alerts = []
        
        # Check system metrics
        if metrics.cpu_usage > 85:
            alerts.append({
                'type': 'high_cpu',
                'severity': 'warning',
                'message': f"High CPU usage: {metrics.cpu_usage:.1f}%",
                'timestamp': time.time()
            })
        
        if metrics.memory_usage > 85:
            alerts.append({
                'type': 'high_memory',
                'severity': 'warning',
                'message': f"High memory usage: {metrics.memory_usage:.1f}%",
                'timestamp': time.time()
            })
        
        if metrics.disk_usage > 90:
            alerts.append({
                'type': 'high_disk',
                'severity': 'critical',
                'message': f"High disk usage: {metrics.disk_usage:.1f}%",
                'timestamp': time.time()
            })
        
        # Check response times
        if metrics.response_time_avg > 5.0:  # 5 seconds
            alerts.append({
                'type': 'slow_response',
                'severity': 'warning',
                'message': f"Slow response times: {metrics.response_time_avg:.2f}s average",
                'timestamp': time.time()
            })
        
        # Add alerts to history
        for alert in alerts:
            self._alerts.append(alert)
            if alert['severity'] == 'critical':
                self.logger.critical(f"CRITICAL ALERT: {alert['message']}")
            else:
                self.logger.warning(f"ALERT: {alert['message']}")
    
    def _log_metrics(self, metrics: PerformanceMetrics):
        """Log current metrics"""
        self.logger.info(
            f"Performance Metrics - "
            f"CPU: {metrics.cpu_usage:.1f}% | "
            f"Memory: {metrics.memory_usage:.1f}% | "
            f"Disk: {metrics.disk_usage:.1f}% | "
            f"Connections: {metrics.network_connections} | "
            f"Blocks: {metrics.blocks_processed} | "
            f"Transactions: {metrics.transactions_processed} | "
            f"Avg Response: {metrics.response_time_avg:.2f}s"
        )
    
    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics"""
        return self.metrics_collector.collect_metrics()
    
    def get_metrics_summary(self, duration_minutes: int = 60) -> Dict[str, Any]:
        """Get metrics summary for specified duration"""
        history = self.metrics_collector.get_metrics_history(duration_minutes)
        
        if not history:
            return {'message': 'No metrics available'}
        
        # Calculate averages
        avg_cpu = sum(m.cpu_usage for m in history) / len(history)
        avg_memory = sum(m.memory_usage for m in history) / len(history)
        avg_disk = sum(m.disk_usage for m in history) / len(history)
        avg_response = sum(m.response_time_avg for m in history) / len(history)
        
        # Get max values
        max_cpu = max(m.cpu_usage for m in history)
        max_memory = max(m.memory_usage for m in history)
        max_disk = max(m.disk_usage for m in history)
        
        # Get latest counters
        latest = history[-1]
        
        return {
            'duration_minutes': duration_minutes,
            'data_points': len(history),
            'averages': {
                'cpu_usage': round(avg_cpu, 2),
                'memory_usage': round(avg_memory, 2),
                'disk_usage': round(avg_disk, 2),
                'response_time': round(avg_response, 2)
            },
            'maximums': {
                'cpu_usage': round(max_cpu, 2),
                'memory_usage': round(max_memory, 2),
                'disk_usage': round(max_disk, 2)
            },
            'current_counters': {
                'consensus_rounds': latest.consensus_rounds,
                'blocks_processed': latest.blocks_processed,
                'transactions_processed': latest.transactions_processed,
                'errors_count': latest.errors_count
            }
        }
    
    def get_health_report(self) -> Dict[str, Any]:
        """Get comprehensive health report"""
        health_status = self.health_checker.get_health_status()
        recent_alerts = list(self._alerts)[-10:]  # Last 10 alerts
        
        return {
            'health_status': health_status,
            'recent_alerts': recent_alerts,
            'alert_summary': {
                'total_alerts': len(self._alerts),
                'critical_alerts': len([a for a in self._alerts if a.get('severity') == 'critical']),
                'warning_alerts': len([a for a in self._alerts if a.get('severity') == 'warning'])
            }
        }
    
    # Convenience methods for incrementing counters
    def record_consensus_round(self):
        """Record a consensus round"""
        self.metrics_collector.increment_counter('consensus_rounds')
    
    def record_block_processed(self):
        """Record a processed block"""
        self.metrics_collector.increment_counter('blocks_processed')
    
    def record_transaction_processed(self):
        """Record a processed transaction"""
        self.metrics_collector.increment_counter('transactions_processed')
    
    def record_error(self):
        """Record an error"""
        self.metrics_collector.increment_counter('errors')
    
    def record_response_time(self, response_time: float):
        """Record response time"""
        self.metrics_collector.record_response_time(response_time)
    
    def time_operation(self, operation_name: str):
        """Context manager for timing operations"""
        return TimedOperation(self.metrics_collector, operation_name)


class TimedOperation:
    """Context manager for timing operations"""
    
    def __init__(self, metrics_collector: MetricsCollector, operation_name: str):
        self.metrics_collector = metrics_collector
        self.operation_name = operation_name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            elapsed = time.time() - self.start_time
            self.metrics_collector.record_response_time(elapsed)
            logging.debug(f"Operation '{self.operation_name}' took {elapsed:.3f}s")
