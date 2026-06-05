"""Benign control for the recursive ClassMethod dependency fixture."""


class Repository:
    def __init__(self, db_connection):
        self._db = db_connection

    def run(self, payload):
        return "ok"


class Service:
    def __init__(self, repository: Repository):
        self._repository = repository

    def run(self, payload):
        return self._repository.run(payload)


class UserController:
    def __init__(self, service: Service):
        self._service = service

    def run(self, payload):
        return self._service.run(payload)
