from abc import ABC, abstractmethod

class Module(ABC):
    # for future compatibility
    def verdict(self):
        return self.provide_verdict()

    @abstractmethod
    def provide_verdict(self):
        pass

    @abstractmethod
    def __str__(self):
        pass

