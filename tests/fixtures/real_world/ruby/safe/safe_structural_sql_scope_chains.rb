require 'shellwords'

class Project < ApplicationRecord
  # Bound date in a mid-chain where: the interpolated table name is a method.
  def self.latest(user = nil, count = 5)
    visible(user).limit(count).
      order(:created_on => :desc).
      where("#{table_name}.created_on >= ?", 30.days.ago).
      to_a
  end

  # A lambda body reads a class-declaration option, not a method parameter.
  def self.acts_as_tree(options = {})
    configuration = { order: nil }
    configuration.update(options)
    scope :roots, lambda {
      where("#{configuration[:foreign_key]} IS NULL").order(configuration[:order])
    }
  end
end

def redis_copy(opts = {})
  src = "#{opts[:srchost]}:#{opts[:srcport]}"
  dst = "#{opts[:dsthost]}:#{opts[:dstport]}"
  `redis-copy #{src.shellescape} #{dst.shellescape}`
end
