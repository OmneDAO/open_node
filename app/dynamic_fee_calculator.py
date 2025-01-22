# dynamic_fee_calculator.py

import logging
import threading
from decimal import Decimal, ROUND_DOWN
from typing import Dict, Any, List
from collections import deque

class DynamicFeeCalculator:
    """
    Calculates dynamic transaction fees based on network conditions and transaction specifics.
    Designed to maintain small, stable fees suitable for everyday internet payments.
    """

    def __init__(self,
                 base_fee: Decimal = Decimal('0.001'),                # Base fee in OMC (reduced)
                 fee_multiplier: Decimal = Decimal('0.005'),          # Multiplier for congestion (less aggressive)
                 gas_price_adjustment: Decimal = Decimal('0.0001'),    # Adjustment per gas unit
                 type_fee_adjustments: Dict[str, Decimal] = None,      # Additional fees based on transaction type (minimal)
                 moving_average_window: int = 100,                     # Number of recent transactions to consider
                 max_fee: Decimal = Decimal('0.005'),                   # Maximum allowable fee (tight cap)
                 min_fee: Decimal = Decimal('0.0001'),                  # Minimum allowable fee (to deter spam)
                 ):
        """
        Initializes the DynamicFeeCalculator with configurable parameters.

        :param base_fee: The base fee applied to all transactions.
        :param fee_multiplier: The fee multiplier based on mempool congestion.
        :param gas_price_adjustment: The fee per gas unit.
        :param type_fee_adjustments: Additional fee adjustments based on transaction type.
        :param moving_average_window: Number of recent transactions to include in moving average.
        :param max_fee: The maximum fee that can be charged for a transaction.
        :param min_fee: The minimum fee that must be charged for a transaction.
        """
        self.base_fee = base_fee
        self.fee_multiplier = fee_multiplier
        self.gas_price_adjustment = gas_price_adjustment
        self.type_fee_adjustments = type_fee_adjustments if type_fee_adjustments else {}
        self.moving_average_window = moving_average_window
        self.max_fee = max_fee
        self.min_fee = min_fee

        # Moving average of recent fees
        self.recent_fees = deque(maxlen=self.moving_average_window)
        self.average_fee = base_fee

        # Lock for thread-safe operations
        self.lock = threading.Lock()

        # Define gas units for different transaction types
        self.gas_unit_mapping = {
            'standard_transfer': Decimal('50'),      # Gas units for a standard transfer
            'deploy_contract': Decimal('200'),       # Gas units for deploying a smart contract
            'execute_contract': Decimal('150'),      # Gas units for executing a smart contract
            'metadata_processing': Decimal('30'),    # Gas units for processing metadata
            # Add more transaction types as needed
        }

        logging.info(f"DynamicFeeCalculator initialized with base_fee={self.base_fee} OMC, "
                     f"fee_multiplier={self.fee_multiplier}, gas_price_adjustment={self.gas_price_adjustment}, "
                     f"max_fee={self.max_fee}, min_fee={self.min_fee}.")

    def get_gas_units(self, transaction: Dict[str, Any]) -> Decimal:
        """
        Determines the gas units consumed by a transaction based on its type.

        :param transaction: The transaction data as a dictionary.
        :return: Total gas units consumed.
        """
        tx_type = transaction.get('type', 'standard_transfer')
        gas_units = self.gas_unit_mapping.get(tx_type, Decimal('50'))  # Default to 50 gas units
        logging.debug(f"Transaction type '{tx_type}' consumes {gas_units} gas units.")
        return gas_units

    def get_dynamic_fee(self, transaction: Dict[str, Any], mempool_size: int, mempool_capacity: int) -> Decimal:
        """
        Calculates the dynamic fee for a given transaction.

        :param transaction: The transaction data as a dictionary.
        :param mempool_size: Current number of transactions in the mempool.
        :param mempool_capacity: Maximum capacity of the mempool.
        :return: Calculated fee as a Decimal.
        """
        with self.lock:
            # 1. Calculate congestion factor
            congestion = Decimal(mempool_size) / Decimal(mempool_capacity)
            congestion_factor = Decimal('1') + (self.fee_multiplier * congestion)
            logging.debug(f"Calculated congestion_factor={congestion_factor} based on mempool_size={mempool_size} "
                          f"and capacity={mempool_capacity}.")

            # 2. Calculate gas units
            gas_units = self.get_gas_units(transaction)

            # 3. Calculate gas fee
            gas_fee = self.gas_price_adjustment * gas_units
            logging.debug(f"Calculated gas_fee={gas_fee} OMC based on gas_units={gas_units} and gas_price_adjustment={self.gas_price_adjustment}.")

            # 4. Calculate type-based fee adjustment (optional)
            tx_type = transaction.get('type', 'standard_transfer')
            type_fee_adj = self.type_fee_adjustments.get(tx_type, Decimal('0'))
            logging.debug(f"Calculated type_fee_adj={type_fee_adj} OMC based on tx_type='{tx_type}'.")

            # 5. Base fee
            fee = self.base_fee

            # 6. Optional priority fee
            priority_fee = Decimal(transaction.get('priority_fee', '0.0000'))  # Defaults to 0 if not provided
            logging.debug(f"Calculated priority_fee={priority_fee} OMC based on transaction.")

            # 7. Total fee calculation
            total_fee = (fee + gas_fee + type_fee_adj + priority_fee) * congestion_factor
            logging.debug(f"Total fee before enforcing min/max: {total_fee} OMC.")

            # 8. Enforce min and max fees
            if total_fee < self.min_fee:
                total_fee = self.min_fee
                logging.debug(f"Total fee adjusted to min_fee={self.min_fee} OMC.")
            elif total_fee > self.max_fee:
                total_fee = self.max_fee
                logging.debug(f"Total fee adjusted to max_fee={self.max_fee} OMC.")

            # 9. Update moving average
            self.recent_fees.append(total_fee)
            self.average_fee = sum(self.recent_fees) / Decimal(len(self.recent_fees))
            logging.debug(f"Updated average_fee={self.average_fee} OMC based on recent_fees.")

            return total_fee.quantize(Decimal('0.0001'), rounding=ROUND_DOWN)  # Adjust precision as needed

    def record_transaction_fee(self, fee: Decimal) -> None:
        """
        Records a transaction fee to update the moving average.

        :param fee: The fee of the transaction.
        """
        with self.lock:
            self.recent_fees.append(fee)
            self.average_fee = sum(self.recent_fees) / Decimal(len(self.recent_fees))
            logging.debug(f"Recorded transaction fee={fee} OMC. Updated average_fee={self.average_fee} OMC.")

    def adjust_fee_parameters(self, **kwargs) -> None:
        """
        Adjusts fee calculation parameters dynamically.

        :param kwargs: Key-value pairs of parameters to adjust.
        """
        with self.lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, Decimal(value))
                    logging.info(f"Adjusted {key} to {value}.")
                else:
                    logging.warning(f"Attempted to adjust unknown parameter '{key}'.")

    def get_average_fee(self) -> Decimal:
        """
        Retrieves the current moving average of transaction fees.

        :return: Average fee as a Decimal.
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
            logging.info("Reset moving average of transaction fees to base_fee.")

    def adjust_base_fee(self, recent_block_utilizations: List[Decimal], target_utilization: Decimal = Decimal('0.75')):
        """
        Adjusts the base fee based on recent block utilizations.

        :param recent_block_utilizations: List of recent block utilization ratios.
        :param target_utilization: Desired block utilization ratio.
        """
        with self.lock:
            if not recent_block_utilizations:
                logging.warning("No recent block utilizations provided for base fee adjustment.")
                return

            average_utilization = sum(recent_block_utilizations) / Decimal(len(recent_block_utilizations))
            adjustment_factor = (average_utilization / target_utilization) - Decimal('1')
            self.base_fee *= (Decimal('1') + self.fee_multiplier * adjustment_factor)
            self.base_fee = max(min(self.base_fee, self.max_fee), self.min_fee)
            logging.info(f"Adjusted base_fee to {self.base_fee} OMC based on average utilization {average_utilization}.")

    def calculate_total_average_fee(self) -> Decimal:
        """
        Calculates the overall average fee from the moving average.

        :return: Total average fee as a Decimal.
        """
        with self.lock:
            return self.average_fee
