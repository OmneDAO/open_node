class GrowOnlySet:
    """
    A Conflict-Free Replicated Data Type (CRDT) for a grow-only set.
    """
    def __init__(self):
        self.elements = set()

    def add(self, element):
        """Add an element to the set."""
        self.elements.add(element)

    def merge(self, other_set):
        """Merge another GrowOnlySet into this one."""
        self.elements.update(other_set.elements)

    def get_elements(self):
        """Get all elements in the set."""
        return self.elements


class Counter:
    """
    A Conflict-Free Replicated Data Type (CRDT) for a counter.
    """
    def __init__(self):
        self.value = 0

    def increment(self, amount=1):
        """Increment the counter by a specified amount."""
        self.value += amount

    def merge(self, other_counter):
        """Merge another Counter into this one by taking the maximum value."""
        self.value = max(self.value, other_counter.value)

    def get_value(self):
        """Get the current value of the counter."""
        return self.value

# Example usage
if __name__ == "__main__":
    # Grow-Only Set example
    set1 = GrowOnlySet()
    set1.add("a")
    set1.add("b")

    set2 = GrowOnlySet()
    set2.add("b")
    set2.add("c")

    set1.merge(set2)
    print("Merged GrowOnlySet:", set1.get_elements())

    # Counter example
    counter1 = Counter()
    counter1.increment(5)

    counter2 = Counter()
    counter2.increment(3)

    counter1.merge(counter2)
    print("Merged Counter Value:", counter1.get_value())