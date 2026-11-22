# Positive fixture: each snippet should trigger the named pattern.

# rb.code_exec.eval
def trigger_eval(code)
  eval(code)
end

# rb.code_exec.instance_eval
def trigger_instance_eval(obj, code)
  obj.instance_eval(code)
end

# rb.code_exec.class_eval
def trigger_class_eval(klass, code)
  klass.class_eval(code)
end

# rb.cmdi.backtick
def trigger_backtick(flag)
  `uname #{flag}`
end

# rb.cmdi.system_interp
def trigger_system_interp(cmd)
  system("run #{cmd}")
end

# rb.deser.yaml_load
def trigger_yaml_load(data)
  YAML.load(data)
end

# rb.deser.marshal_load
def trigger_marshal_load(data)
  Marshal.load(data)
end

# rb.reflection.send_dynamic
def trigger_send_dynamic(obj, method_name)
  obj.send(method_name)
end

# rb.reflection.constantize
def trigger_constantize(name)
  name.constantize
end

# rb.ssrf.open_uri
def trigger_open_uri
  open("https://example.com/api")
end
