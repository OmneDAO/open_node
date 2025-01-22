# storage_backend.py

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from block import Block

class StorageBackend(ABC):
    @abstractmethod
    def initialize(self):
        pass

    @abstractmethod
    def save_block(self, block: Block) -> bool:
        pass

    @abstractmethod
    def get_block_by_index(self, index: int) -> Optional[Block]:
        pass

    @abstractmethod
    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        pass

    @abstractmethod
    def load_all_blocks(self) -> List[Block]:
        pass

    @abstractmethod
    def clear_all(self):
        pass
