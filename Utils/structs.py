class Field:
    def __init__(self, name, offset, size, type):
        self.name = name
        self.offset = offset
        self.size = size
        self.type = type

    def __repr__(self):
        return repr((self.name, self.offset, self.size, self.type))
