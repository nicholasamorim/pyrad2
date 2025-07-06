from typing import Any, Dict, Hashable


class BiDict:
    def __init__(self) -> None:
        self.forward: Dict[Hashable, Any] = {}
        self.backward: Dict[Hashable, Any] = {}

    def Add(self, one: Hashable, two: Hashable) -> None:
        self.forward[one] = two
        self.backward[two] = one

    def __len__(self) -> int:
        return len(self.forward)

    def __getitem__(self, key: Hashable) -> Any:
        return self.GetForward(key)

    def __delitem__(self, key: Hashable) -> None:
        if key in self.forward:
            del self.backward[self.forward[key]]
            del self.forward[key]
        else:
            del self.forward[self.backward[key]]
            del self.backward[key]

    def GetForward(self, key: Hashable) -> Any:
        return self.forward[key]

    def HasForward(self, key: Hashable) -> bool:
        return key in self.forward

    def GetBackward(self, key: Hashable) -> Any:
        return self.backward[key]

    def HasBackward(self, key: Hashable) -> bool:
        return key in self.backward
