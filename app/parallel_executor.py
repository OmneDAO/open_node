import threading
from typing import Callable, List, Dict

class ParallelExecutor:
    """
    A scheduler to execute tasks for independent shards in parallel threads.
    """

    def __init__(self):
        self.lock = threading.Lock()

    def execute_in_parallel(self, shard_tasks: Dict[int, Callable[[], None]]) -> None:
        """
        Execute tasks for each shard in parallel.

        Args:
            shard_tasks: A dictionary where keys are shard keys and values are tasks (functions) to execute.
        """
        threads = []

        for shard_key, task in shard_tasks.items():
            thread = threading.Thread(target=self._execute_task, args=(shard_key, task))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def _execute_task(self, shard_key: int, task: Callable[[], None]) -> None:
        """
        Execute a single task for a shard.

        Args:
            shard_key: The shard key associated with the task.
            task: The task (function) to execute.
        """
        with self.lock:
            print(f"Executing task for shard {shard_key}")
        task()

# Example usage
if __name__ == "__main__":
    def task1():
        print("Task 1 executed")

    def task2():
        print("Task 2 executed")

    executor = ParallelExecutor()
    shard_tasks = {
        0: task1,
        1: task2
    }
    executor.execute_in_parallel(shard_tasks)