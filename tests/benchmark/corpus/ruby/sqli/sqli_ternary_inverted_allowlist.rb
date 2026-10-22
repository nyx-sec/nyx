class PostsController < ApplicationController
  SORTABLE = %w[title created_at].freeze

  def index
    requested = params[:sort]
    sort = SORTABLE.include?(requested) ? 'created_at' : requested
    @posts = Post.order(sort).limit(20)
    render json: @posts
  end
end
