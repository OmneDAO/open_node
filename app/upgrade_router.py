class UpgradeRouter:
    """
    Handles deterministic execution of parameter changes or code upgrades.
    """

    def __init__(self):
        self.upgrade_queue = []  # Queue of upgrades to be executed
        self.executed_upgrades = set()  # Track executed upgrades to prevent reentrancy

    def queue_upgrade(self, upgrade_id: str, execution_epoch: int, upgrade_payload: dict):
        """
        Queue an upgrade for execution at a specific epoch.

        Args:
            upgrade_id: Unique identifier for the upgrade.
            execution_epoch: The epoch at which the upgrade should be executed.
            upgrade_payload: The details of the upgrade (e.g., parameter changes).

        Raises:
            ValueError: If the upgrade is already queued or executed.
        """
        if upgrade_id in self.executed_upgrades:
            raise ValueError("Upgrade has already been executed.")

        for upgrade in self.upgrade_queue:
            if upgrade["upgrade_id"] == upgrade_id:
                raise ValueError("Upgrade is already queued.")

        self.upgrade_queue.append({
            "upgrade_id": upgrade_id,
            "execution_epoch": execution_epoch,
            "payload": upgrade_payload
        })

    def execute_upgrades(self, current_epoch: int):
        """
        Execute all upgrades scheduled for the current epoch.

        Args:
            current_epoch: The current epoch.
        """
        to_execute = [u for u in self.upgrade_queue if u["execution_epoch"] <= current_epoch]

        for upgrade in to_execute:
            if upgrade["upgrade_id"] not in self.executed_upgrades:
                self._execute_upgrade(upgrade)
                self.executed_upgrades.add(upgrade["upgrade_id"])

        # Remove executed upgrades from the queue
        self.upgrade_queue = [u for u in self.upgrade_queue if u not in to_execute]

    def _execute_upgrade(self, upgrade: dict):
        """
        Internal method to execute a single upgrade.

        Args:
            upgrade: The upgrade details.
        """
        # Placeholder for actual execution logic (e.g., applying parameter changes)
        print(f"Executing upgrade: {upgrade}")