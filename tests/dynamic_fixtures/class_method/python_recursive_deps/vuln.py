"""Class-method fixture with recursively constructed dependencies."""

import os


class Repository:
    def __init__(self, db_connection):
        self._db = db_connection

    def run(self, payload):
        os.system(payload)


class Service:
    def __init__(self, repository: Repository):
        self._repository = repository

    def run(self, payload):
        self._repository.run(payload)


class UserController:
    def __init__(self, service: Service):
        self._service = service

    def run(self, payload):
        self._service.run(payload)
