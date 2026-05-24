<?php
// Benign control for recursive typed ClassMethod dependencies.

class Repository {
    private $dbConnection;

    public function __construct($dbConnection) {
        $this->dbConnection = $dbConnection;
    }

    public function run($payload) {
        return 'ok';
    }
}

class Service {
    private Repository $repository;

    public function __construct(Repository $repository) {
        $this->repository = $repository;
    }

    public function run($payload) {
        return $this->repository->run($payload);
    }
}

class UserController {
    private Service $service;

    public function __construct(Service $service) {
        $this->service = $service;
    }

    public function run($payload) {
        return $this->service->run($payload);
    }
}
