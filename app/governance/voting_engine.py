class VotingEngine:
    """
    Handles stake-weighted vote tallying for governance polls.
    """

    def __init__(self, staking_manager):
        self.staking_manager = staking_manager  # Reference to the staking manager

    def tally_votes(self, poll):
        """
        Tally votes for a given governance poll.

        Args:
            poll: The GovernancePoll object.

        Returns:
            dict: The final tally of votes.
        """
        results = poll.get_results()
        total_stake = sum(self.staking_manager.get_stake(voter) for voter in results.keys())

        weighted_results = {
            option: (votes / total_stake) * 100 if total_stake > 0 else 0
            for option, votes in results.items()
        }

        return weighted_results

    def emit_vote_result(self, poll_id, results):
        """
        Emit the results of a governance poll.

        Args:
            poll_id: The ID of the poll.
            results: The final tally of votes.
        """
        # Placeholder for emitting the results (e.g., logging or broadcasting)
        print(f"Poll {poll_id} results: {results}")