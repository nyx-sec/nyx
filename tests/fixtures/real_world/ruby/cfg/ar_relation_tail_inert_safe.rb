class FeedCleaner
  def remove(from_account, ids)
    from_account.statuses.select(:id, :reblog_of_id).where(id: ids).reorder(nil).find_each do |status|
      status.touch
    end
  end

  def sorted_emojis
    CustomEmoji.local.left_joins(:category).reorder(CustomEmojiCategory.arel_table[:name].asc).order(shortcode: :asc)
  end

  def domain_mentions(domain)
    Mention
      .joins(:account)
      .merge(Account.with_domain(domain))
      .select(1).arel.exists
  end
end
