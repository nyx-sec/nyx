# Real-repo precision fixture — sister of
# `safe_rails_private_callback_helper.rb`.  Some Rails controllers
# (and many older codebases) name `set_X` / `find_X` helpers WITHOUT
# the canonical `private` directive.  The helpers are still invoked
# only as `before_action` callbacks, never as routes — Rails will
# happily dispatch to a "public" method shaped like an action, but a
# method named in `before_action :name` is a callback target by
# convention.
#
# Pre-fix: the helper showed up as a RouteHandler with
# `Account.find(params[:id])` flagged as missing ownership.
# Post-fix: callback-target name suppression skips the helper unit
# even when no `private` directive is present.
class WidgetsController < ApplicationController
  before_action :authenticate_user!
  before_action :set_widget, only: [:show, :update]

  def show
    authorize @widget, :show?
    render json: @widget
  end

  def update
    authorize @widget, :update?
    @widget.update!(widget_params)
  end

  def set_widget
    @widget = Widget.find(params[:id])
  end

  def widget_params
    params.require(:widget).permit(:title, :body)
  end
end
