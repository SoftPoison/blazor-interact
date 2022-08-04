class Counter:
    __ctr: int

    def __init__(self, start=0) -> None:
        self.__ctr = start

    def get(self):
        v = self.__ctr
        self.__ctr += 1
        return v
