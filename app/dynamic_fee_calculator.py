import logging
import threading
from decimal import Decimal, ROUND_DOWN
from typing import Dict, Any, List
from collections import deque
import json
from datetime import datetime, timezone, date

# Define a DecimalEncoder if needed for JSON serialization.
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return format(obj, 'f')  # Force fixed-point format
        return super().default(obj)

class DynamicFeeCalculator:
    """
    Calculates dynamic transaction fees based on network conditions and transaction specifics.
    This implementation uses gas units as defined in a gas unit mapping and adjusts the fee based on mempool congestion.
    """
    def __init__(self,
             base_fee: Decimal = Decimal('0.0000000000000001'),
             fee_multiplier: Decimal = Decimal('0.00000000000001'),
             gas_price_adjustment: Decimal = Decimal('0.000000000000001'),
             type_fee_adjustments: Dict[str, Decimal] = None,
             moving_average_window: int = 100,
             max_fee: Decimal = Decimal('0.0000000000001'),
             min_fee: Decimal = Decimal('0.00000000000000001')):
        self.base_fee = base_fee
        self.fee_multiplier = fee_multiplier
        self.gas_price_adjustment = gas_price_adjustment
        self.type_fee_adjustments = type_fee_adjustments if type_fee_adjustments else {
            'deploy_contract': Decimal('0.00000000000001'),
            'execute_contract': Decimal('0.000000000000005'),
            'standard_transfer': Decimal('0.0')
        }
        self.moving_average_window = moving_average_window
        self.max_fee = max_fee
        self.min_fee = min_fee

        # Use much smaller gas units for standard transfers.
        self.gas_unit_mapping = {
            'standard_transfer': Decimal('1'),
            'deploy_contract': Decimal('10'),
            'execute_contract': Decimal('8'),
            'metadata_processing': Decimal('1'),
        }

        logging.info(f"DynamicFeeCalculator initialized with base_fee={self.base_fee} OMC, "
                    f"fee_multiplier={self.fee_multiplier}, gas_price_adjustment={self.gas_price_adjustment}, "
                    f"max_fee={self.max_fee}, min_fee={self.min_fee}.")
        self.recent_fees = deque(maxlen=self.moving_average_window)
        self.average_fee = base_fee
        self.lock = threading.Lock()
        
    def get_gas_units(self, transaction: Dict[str, Any]) -> Decimal:
        """
        Determines the gas units consumed by a transaction based on its type.
        
        :param transaction: The transaction data as a dictionary.
        :return: The gas units consumed.
        """
        tx_type = transaction.get('type', 'standard_transfer')
        gas_units = self.gas_unit_mapping.get(tx_type, Decimal('50'))
        logging.debug(f"Transaction type '{tx_type}' uses {gas_units} gas units.")
        return gas_units

    def get_dynamic_fee(self, transaction: Dict[str, Any], mempool_size: int, mempool_capacity: int) -> Decimal:
        """
        Calculates the dynamic fee for a transaction.
        
        :param transaction: The transaction data as a dictionary.
        :param mempool_size: Current number of transactions in the mempool.
        :param mempool_capacity: The maximum capacity of the mempool.
        :return: The calculated fee as a Decimal.
        """
        with self.lock:
            # 1. Compute congestion factor.
            if mempool_capacity == 0:
                congestion_factor = Decimal('1')
            else:
                congestion = Decimal(mempool_size) / Decimal(mempool_capacity)
                congestion_factor = Decimal('1') + (self.fee_multiplier * congestion)
            logging.debug(f"Congestion factor: {congestion_factor}")

            # 2. Calculate gas fee.
            gas_units = self.get_gas_units(transaction)
            gas_fee = self.gas_price_adjustment * gas_units
            logging.debug(f"Gas fee: {gas_fee} OMC (gas_units: {gas_units})")

            # 3. Calculate type-based fee adjustment.
            tx_type = transaction.get('type', 'standard_transfer')
            type_fee_adj = self.type_fee_adjustments.get(tx_type, Decimal('0'))
            logging.debug(f"Type fee adjustment for '{tx_type}': {type_fee_adj} OMC")

            # 4. Get any priority fee provided in the transaction.
            priority_fee = Decimal(transaction.get('priority_fee', '0.0000'))
            logging.debug(f"Priority fee: {priority_fee} OMC")

            # 5. Calculate total fee.
            total_fee = (self.base_fee + gas_fee + type_fee_adj + priority_fee) * congestion_factor
            logging.debug(f"Total fee before limits: {total_fee} OMC")

            # 6. Enforce minimum and maximum fee limits.
            if total_fee < self.min_fee:
                total_fee = self.min_fee
                logging.debug(f"Total fee adjusted to min_fee: {self.min_fee} OMC")
            elif total_fee > self.max_fee:
                total_fee = self.max_fee
                logging.debug(f"Total fee adjusted to max_fee: {self.max_fee} OMC")

            # 7. Update moving average.
            self.recent_fees.append(total_fee)
            self.average_fee = sum(self.recent_fees) / Decimal(len(self.recent_fees))
            logging.debug(f"Updated average fee: {self.average_fee} OMC")

            return total_fee.quantize(Decimal('0.0000000000000001'), rounding=ROUND_DOWN)

    def record_transaction_fee(self, fee: Decimal) -> None:
        """
        Records a transaction fee to update the moving average.
        
        :param fee: The fee to record.
        """
        with self.lock:
            self.recent_fees.append(fee)
            self.average_fee = sum(self.recent_fees) / Decimal(len(self.recent_fees))
            logging.debug(f"Recorded fee: {fee} OMC. New average fee: {self.average_fee} OMC.")

    def adjust_fee_parameters(self, **kwargs) -> None:
        """
        Adjusts fee parameters dynamically.
        
        :param kwargs: Key-value pairs of parameters to adjust.
        """
        with self.lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, Decimal(value))
                    logging.info(f"Adjusted {key} to {value}.")
                else:
                    logging.warning(f"Unknown parameter: {key}.")

    def get_average_fee(self) -> Decimal:
        """
        Retrieves the current moving average fee.
        
        :return: The average fee as a Decimal.
        """
        with self.lock:
            return self.average_fee

    def reset_moving_average(self) -> None:
        """
        Resets the moving average of transaction fees.
        """
        with self.lock:
            self.recent_fees.clear()
            self.average_fee = self.base_fee
            logging.info("Reset moving average to base_fee.")

    def adjust_base_fee(self, recent_block_utilizations: List[Decimal], target_utilization: Decimal = Decimal('0.75')):
        """
        Adjusts the base fee based on recent block utilizations.
        
        :param recent_block_utilizations: A list of block utilization ratios.
        :param target_utilization: The target utilization ratio.
        """
        with self.lock:
            if not recent_block_utilizations:
                logging.warning("No block utilizations provided for base fee adjustment.")
                return
            average_utilization = sum(recent_block_utilizations) / Decimal(len(recent_block_utilizations))
            adjustment_factor = (average_utilization / target_utilization) - Decimal('1')
            self.base_fee *= (Decimal('1') + self.fee_multiplier * adjustment_factor)
            self.base_fee = max(min(self.base_fee, self.max_fee), self.min_fee)
            logging.info(f"Adjusted base_fee to {self.base_fee} OMC based on average utilization {average_utilization}.")

    def calculate_total_average_fee(self) -> Decimal:
        """
        Calculates the overall average fee from recent transactions.
        
        :return: The total average fee as a Decimal.
        """
        with self.lock:
            return self.average_fee
