# Real-repo precision fixture distilled from
# mastodon/app/controllers/admin/accounts_controller.rb#set_account
# (and 100+ sibling controllers).  Rails canonical pattern: the
# controller registers a `before_action :set_X` whose target is a
# private helper that does the row-fetch.  Per-record authorization
# (e.g. `authorize @account, :show?`) lives in the public action that
# triggers the callback, not in the callback itself.
#
# Pre-fix: `set_account` was emitted as a RouteHandler unit and
# `Account.find(params[:id])` was flagged as missing ownership.
# Post-fix: the Rails extractor skips private methods AND methods
# named in `before_action`/`after_action` directives, so no unit is
# created for the helper.  The public action `show` carries the
# authorize check and is itself a route, but its body has no
# sensitive read operation, so no auth-rule finding is produced.
class AccountsController < ApplicationController
  before_action :authenticate_user!
  before_action :set_account, only: [:show, :update, :destroy]

  def show
    authorize @account, :show?
    render json: @account
  end

  def update
    authorize @account, :update?
    @account.update!(account_params)
  end

  def destroy
    authorize @account, :destroy?
    @account.destroy!
  end

  private

  def set_account
    @account = Account.find(params[:id])
  end

  def account_params
    params.require(:account).permit(:display_name, :note)
  end
end
