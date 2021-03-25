import os
import tempfile

from autocert.cache import Cache


def test_read_write():
    name = 'foobar.txt'
    data = b'hello world'
    with tempfile.TemporaryDirectory() as temp_dir:
        cache = Cache(temp_dir)
        cache.write(name, data)
        assert cache.read(name) == data


def test_path():
    name = 'foobar.txt'
    with tempfile.TemporaryDirectory() as temp_dir:
        cache = Cache(temp_dir)
        assert cache.path(name) == os.path.join(temp_dir, name)


def test_exists():
    name = 'foobar.txt'
    data = b'hello world'
    with tempfile.TemporaryDirectory() as temp_dir:
        cache = Cache(temp_dir)
        assert cache.exists(name) == False
        cache.write(name, data)
        assert cache.exists(name) == True
