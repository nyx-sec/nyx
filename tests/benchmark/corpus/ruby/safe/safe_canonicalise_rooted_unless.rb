# ruby-safe-021: File.expand_path + `unless start_with?` with a non-literal
# prefix (configured root reachable through a method call).  The opaque
# prefix-lock combined with `expand_path`'s dotdot=No proof is sufficient
# under PathFact::is_path_traversal_safe to suppress the FILE_IO sink.
class Config
  def root
    '/srv/app/uploads'
  end
end

def serve(env, config)
  path = env['PATH_INFO']
  filename = File.expand_path(File.join(config.root, path))
  unless filename.start_with? config.root
    return [403, {}, []]
  end
  File.read(filename)
end
