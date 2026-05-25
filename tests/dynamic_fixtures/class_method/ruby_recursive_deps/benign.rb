# Benign control for recursively constructed Ruby dependencies.
class ShellRunner
  def run(command)
    command.gsub('NYX_PWN_CMDI', '')
  end
end

class UserRepository
  def initialize(shell_runner)
    @shell_runner = shell_runner
  end

  def find(input)
    @shell_runner.run(input)
  end
end

class UserService
  def initialize(user_repository)
    @user_repository = user_repository
  end

  def run(input)
    @user_repository.find(input)
  end
end
