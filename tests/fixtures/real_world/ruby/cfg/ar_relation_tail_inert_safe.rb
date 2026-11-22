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

  def spent_hours(user)
    TimeEntry.visible(user).joins(:issue).
      joins("JOIN #{Issue.table_name} parent ON parent.root_id = #{Issue.table_name}.root_id" +
            " AND parent.lft <= #{Issue.table_name}.lft").
      where("parent.id > ?", 0).group(:project_id).sum(:hours)
  end
end
