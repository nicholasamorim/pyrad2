from typing import Any, Dict, Hashable


class BiDict:
    """BiDict (Bidirectional Dictionary) provides a one-to-one mapping
    between keys and values.

    Supports both forward and reverse lookup.
    """

    def __init__(self) -> None:
        """Initialize empty forward and reverse dictionaries."""
        self.forward: Dict[Hashable, Any] = {}
        self.backward: Dict[Hashable, Any] = {}

    def __len__(self) -> int:
        """Return the number of entries in the dictionary."""
        return len(self.forward)

    def __getitem__(self, key: Hashable) -> Any:
        """Retrieve the value associated with the given key."""
        return self.get_forward(key)

    def __delitem__(self, key: Hashable) -> None:
        """Remove key and its associated value from the dictionary."""
        if key in self.forward:
            del self.backward[self.forward[key]]
            del self.forward[key]
        else:
            del self.forward[self.backward[key]]
            del self.backward[key]

    def add(self, one: Hashable, two: Hashable) -> None:
        """Add a bidirectional mapping between 'one' and 'two'."""
        self.forward[one] = two
        self.backward[two] = one

    def get_forward(self, key: Hashable) -> Any:
        """Return the value associated with 'key' from the forward mapping."""
        return self.forward[key]

    def has_forward(self, key: Hashable) -> bool:
        """Check if 'key' exists in the forward mapping."""
        return key in self.forward

    def get_backward(self, key: Hashable) -> Any:
        """Return the key associated with 'value' from the reverse mapping."""
        return self.backward[key]

    def has_backward(self, key: Hashable) -> bool:
        """Check if 'value' exists in the reverse mapping."""
        return key in self.backward
