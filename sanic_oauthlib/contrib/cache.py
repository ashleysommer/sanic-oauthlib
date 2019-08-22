# coding: utf-8
from os import path
from pickle import Pickler, Unpickler


class NullCache(object):

    def __getattr__(self, item):
        return None

    def __setattr__(self, key, value):
        return


class SimpleCache(object):
    __slots__ = ("_sc_cache", "_sc_threshold", "_sc_key_list")

    def __init__(self, threshold=1000):
        self._sc_threshold = threshold
        self._sc_key_list = []
        self._sc_cache = {}

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            try:
                _sc_key_list = self._sc_key_list
                obj = self._sc_cache[key]
                if _sc_key_list.index(key) < len(_sc_key_list) - 1:
                    _sc_key_list.remove(key)
                    _sc_key_list.append(key)
                return obj
            except KeyError:
                raise AttributeError(key)

    def __setattr__(self, key, value):
        try:
            object.__setattr__(self, key, value)
        except (AttributeError, ValueError):
            try:
                self._sc_key_list.remove(key)
            except ValueError:
                pass
            self._sc_cache[key] = value
            self._sc_key_list.append(key)
            self._adj_threshold()
        return

    def _adj_threshold(self):
        while len(self._sc_key_list) > self._sc_threshold:
            first_key = self._sc_key_list.pop(0)
            self._sc_cache.__delitem__(first_key)


class FileSystemCache(object):
    __slots__ = ("_fsc_filename", "_fsc_threshold")

    def __init__(self, directory, filename=None, threshold=1000):
        self._fsc_threshold = threshold
        if directory is None:
            directory = path.curdir
        if filename is None:
            filename = "sanic_oauth_cache.pickle"
        self._fsc_filename = path.join(directory, filename)
        try:
            _cache = self._fss_unpickler()
        except FileNotFoundError:
            _cache = dict()
            _cache['_fsc_key_list'] = list()
            self._fsc_pickler(_cache)

    def _fsc_pickler(self, obj):
        with open(self._fsc_filename, 'wb') as f:
            p = Pickler(f, 4)
            p.dump(obj)

    def _fsc_unpickler(self):
        with open(self._fsc_filename, 'rb') as f:
            p = Unpickler(f)
            return p.load()

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            _cache = self._fsc_unpickler()
            _fsc_key_list = _cache.get('_fsc_key_list')
            try:
                obj = self._cache[key]
                if _fsc_key_list.index(key) < len(_fsc_key_list) - 1:
                    _fsc_key_list.remove(key)
                    _fsc_key_list.append(key)
                    _cache['_fsc_key_list'] = _fsc_key_list
                    self._fsc_pickler(_cache)
                return obj
            except KeyError:
                raise AttributeError(key)

    def __setattr__(self, key, value):
        try:
            object.__setattr__(self, key, value)
        except (AttributeError, ValueError):
            _cache = self._fsc_unpickler()
            _fsc_key_list = _cache.get('_fsc_key_list')
            try:
                _fsc_key_list.remove(key)
            except ValueError:
                pass
            _cache[key] = value
            _fsc_key_list.append(key)
            self._adj_threshold(_cache)
            self._fsc_pickler(_cache)
        return

    def _adj_threshold(self, _cache):
        _fsc_key_list = _cache.get('_fsc_key_list')
        while len(_fsc_key_list) > self._fsc_threshold:
            first_key = _fsc_key_list.pop(0)
            _cache.__delitem__(first_key)
        _cache['_fsc_key_list'] = _fsc_key_list


class Cache(object):
    def __init__(self, app, config_prefix='OAUTHLIB', **kwargs):
        self.config_prefix = config_prefix
        self.config = app.config

        cache_type = '_%s' % self._config('type')
        kwargs.update(dict(
            default_timeout=self._config('DEFAULT_TIMEOUT', 100)
        ))

        try:
            self.cache = getattr(self, cache_type)(**kwargs)
        except AttributeError:
            raise RuntimeError(
                '`%s` is not a valid cache type!' % cache_type
            )
        app.extensions[config_prefix.lower() + '_cache'] = self.cache

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            try:
                return getattr(self.cache, key)
            except AttributeError:
                raise AttributeError('No such attribute: %s' % key)

    def _config(self, key, default='error'):
        key = key.upper()
        prior = '%s_CACHE_%s' % (self.config_prefix, key)
        if prior in self.config:
            return self.config[prior]
        fallback = 'CACHE_%s' % key
        if fallback in self.config:
            return self.config[fallback]
        if default == 'error':
            raise RuntimeError('%s is missing.' % prior)
        return default

    def _null(self, **kwargs):
        """Returns a :class:`NullCache` instance"""
        return NullCache()

    def _simple(self, **kwargs):
        """Returns a :class:`SimpleCache` instance

        .. warning::

            This cache system might not be thread safe. Use with caution.
        """
        kwargs.update(dict(threshold=self._config('threshold', 500)))
        return SimpleCache(**kwargs)

    def _memcache(self, **kwargs):
        """Returns a :class:`MemcachedCache` instance"""
        raise NotImplementedError("Sanic-OAuthLib doesn't implement a Memcached Cache")

    def _redis(self, **kwargs):
        """Returns a :class:`RedisCache` instance"""
        raise NotImplementedError("Sanic-OAuthLib doesn't implement a Redis Cache")

    def _filesystem(self, **kwargs):
        """Returns a :class:`FileSystemCache` instance"""
        kwargs.update(dict(
            threshold=self._config('threshold', 500),
        ))
        return FileSystemCache(self._config('dir', None), **kwargs)
