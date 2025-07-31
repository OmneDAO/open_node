from typing import Dict, List, Optional
from asyncio import Queue
from threading import Lock, Event
import asyncio
import logging
from datetime import datetime, timezone

class TransactionQueue:
    """
    Thread-safe transaction queue with async support and proper error handling.
    """
    def __init__(self, max_size: int = 10000):
        self.queue = Queue(maxsize=max_size)
        self.lock = Lock()
        self.event = Event()
        self.logger = logging.getLogger(__name__)
        self.max_size = max_size
        self._processing = False
        self._shutdown = False

    async def put(self, transaction: Dict) -> bool:
        """
        Asynchronously put a transaction in the queue.
        Returns True if successful, False if queue is full.
        """
        try:
            if self.queue.qsize() >= self.max_size:
                self.logger.warning("Transaction queue is full")
                return False
            
            await self.queue.put(transaction)
            self.event.set()  # Signal that new data is available
            return True
        except Exception as e:
            self.logger.error(f"Error putting transaction in queue: {e}")
            return False

    async def get_batch(self, max_size: int = 100, timeout: float = 1.0) -> List[Dict]:
        """
        Asynchronously get a batch of transactions from the queue.
        Returns empty list if no transactions available within timeout.
        """
        try:
            transactions = []
            start_time = datetime.now(timezone.utc)
            
            while len(transactions) < max_size:
                if self.queue.empty():
                    if (datetime.now(timezone.utc) - start_time).total_seconds() > timeout:
                        break
                    await asyncio.sleep(0.1)  # Wait a bit before checking again
                    continue
                
                try:
                    transaction = await self.queue.get()
                    transactions.append(transaction)
                except asyncio.QueueEmpty:
                    break
                    
            return transactions
        except Exception as e:
            self.logger.error(f"Error getting batch from queue: {e}")
            return []

    def size(self) -> int:
        """Get the current size of the queue."""
        return self.queue.qsize()

    def clear(self) -> None:
        """Clear all transactions from the queue."""
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    def is_empty(self) -> bool:
        """Check if the queue is empty."""
        return self.queue.empty()

    def shutdown(self) -> None:
        """Shutdown the queue."""
        self._shutdown = True
        self.clear()
        self.event.set()

    def is_shutdown(self) -> bool:
        """Check if the queue is shutdown."""
        return self._shutdown 