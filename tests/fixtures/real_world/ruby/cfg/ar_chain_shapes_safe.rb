class Replies
  def set_replies(only_other, account, status)
    replies = only_other ? Status.where.not(account_id: account.id).joins(:account).merge(Account.without_suspended) : account.statuses
    replies = replies.where(in_reply_to_id: status.id)
    replies
  end

  def total(domain)
    MediaAttachment.joins(:account).merge(Account.where(domain: domain)).sum(:size)
  end

  def pluck_ids(scope, limit)
    scope.merge(cond).limit(limit).pluck(:id).zip([key].cycle)
  end

  def cleanup(to_delete)
    PreviewCardTrend.where(preview_card_id: to_delete.map { |(_, c)| c.id }).delete_all if to_delete.any?
  end

  def over_threshold?(scope, sub, threshold)
    scope.where(created_at: sub.timeframe_start..).count >= threshold
  end
end
