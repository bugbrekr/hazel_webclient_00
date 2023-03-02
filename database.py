import collections.abc
import re
import time
import plyvel
import secrets
import msgpack
import json
from collections import UserDict

class DB(object):
    def __init__(self, db_location):
        self.db = plyvel.DB(db_location, create_if_missing=True)
        super(DB, self).__init__()
    def _update_dict(self, d, u):
        if d==None or not isinstance(d, dict)==True: return u
        for k, v in u.items():
            if isinstance(v, collections.abc.Mapping):
                d[k] = self._update_dict(d.get(k, {}), v)
            else:
                d[k] = v
        return d
    def __getitem__(self, key):
        return self.get(key)
    def __setitem__(self, key, data):
        return self.put(key, data)
    def __delitem__(self, key):
        return self.delete(key)
    def __len__(self):
        return len(list(self.list_keys()))
    def __repr__(self):
        return json.dumps({i[0]:i[1] for i in self.list()}, indent=4)
    def __iter__(self):
        return self.list()
    def __unicode__(self):
        return unicode(self.__repr__())
    def __contains__(self, item):
        return item in list(self.list_keys())

    def keys(self):
        return list(self.list_keys())
    def values(self):
        return list([i[1] for i in self.list()])
    def items(self):
        return [(i[0],i[1]) for i in self.list()]
    def pop(self, key):
        self.delete(key)
        return self.get(key)

    def get(self, key):
        d = self.db.get(key.encode())
        if d == None:
            return None
        return msgpack.unpackb(d)

    def put(self, key, data):
        self.db.put(key.encode(), msgpack.packb(data), sync=True)

    def update(self, key, data):
        data = self._update_dict(self.get(key), data)
        self.put(key, data)

    def delete(self, key):
        self.db.delete(key.encode(), sync=True)

    def list(self):
        for key, value in self.db:
            yield (key.decode(), msgpack.unpackb(value))

    def list_keys(self):
        for key, _ in self.db:
            yield key.decode()

if __name__ == '__main__':
    db = DB("security_databases/known_clients")
    # db["127.0.0.1"] = {
    #         "logins": [],
    #         "failed_attempts": [],
    #         "failed_attempt_count": 0,
    #         "is_trusted": True
    #     }
    # db["192.168.0.107"] = {
    #         "logins": [],
    #         "failed_attempts": [],
    #         "failed_attempt_count": 0,
    #         "is_blacklisted": True
    #     }
    # db["192.168.0.107"] = db["192.168.0.107"].pop("is_trusted")
    print(db)
