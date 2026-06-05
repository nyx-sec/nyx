'use strict';
const { execSync } = require('child_process');

class ShellRunner {
    run(command) {
        return execSync('true ' + command).toString();
    }
}

class UserRepository {
    constructor(shellRunner) {
        this.shellRunner = shellRunner;
    }

    find(input) {
        return this.shellRunner.run(input);
    }
}

class UserService {
    constructor(userRepository) {
        this.userRepository = userRepository;
    }

    run(input) {
        return this.userRepository.find(input);
    }
}

module.exports = { UserService, UserRepository, ShellRunner };
