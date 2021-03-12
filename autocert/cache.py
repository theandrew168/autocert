import os


class Cache:

    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

    def path(self, name):
        return os.path.join(self.cache_dir, name)

    def exists(self, name):
        path = os.path.join(self.cache_dir, name)
        return os.path.exists(path)

    def read(self, name):
        path = os.path.join(self.cache_dir, name)
        with open(path, 'rb') as f:
            data = f.read()
        return data

    def write(self, name, data):
        path = os.path.join(self.cache_dir, name)
        with open(path, 'wb') as f:
            f.write(data)
