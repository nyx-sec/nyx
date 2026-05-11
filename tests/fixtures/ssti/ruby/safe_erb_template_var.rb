# Safe-template-var: render an on-disk template via Rails-style
# `render :template, locals: {...}`.  The template name is a constant
# symbol; the locals carry user input but flow into a file-loaded
# template, not into a source string.

def handler(params)
  render template: "users/show", locals: { name: params[:name] }
end
