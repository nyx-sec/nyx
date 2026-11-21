class PolicyScopeNotesController < ApplicationController
  def show
    @note = policy_scope(Note).find(params[:id])
  end

  def update
    note = policy_scope(Note).find(params[:id])
    note.update(body: params[:body])
  end
end
