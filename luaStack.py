class LuaStack:
    stack = []

    def __init__(self, stack = []):
        self.stack = stack

    def pop(self):
        return self.stack.pop()

    def push(self, item):
        self.stack.append(item)

    def clear(self):
        self.stack.clear()

    def Clone(self):
        return LuaStack(self.stack.copy())
