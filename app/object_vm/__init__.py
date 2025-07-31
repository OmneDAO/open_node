# object_vm package
from .dispatcher import ParallelDispatcher
from .vm import run_object_tx

__all__ = ['ParallelDispatcher', 'run_object_tx']
