import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Callable

class ParallelDispatcher:
    """
    A dispatcher to execute non-conflicting transactions in parallel.
    """
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.lock = threading.Lock()

    def execute(self, tasks: List[Callable[[], Dict]]) -> List[Dict]:
        """
        Execute a list of tasks in parallel.

        Args:
            tasks: A list of callables representing the tasks to execute.

        Returns:
            A list of results from the executed tasks.
        """
        futures = [self.executor.submit(task) for task in tasks]
        results = []
        for future in futures:
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"error": str(e)})
        return results

    def shutdown(self):
        """
        Shutdown the executor.
        """
        self.executor.shutdown(wait=True)