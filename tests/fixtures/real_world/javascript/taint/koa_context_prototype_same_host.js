// Same prototype with a same-host check: the redirect target is only used
// when it resolves to this server's own host.
module.exports = {
  redirect(url) {
    this.set('Location', url)
    this.status = 302
  },

  back(alt) {
    const referrer = this.ctx.get('Referrer')
    if (referrer) {
      const url = new URL(referrer, this.ctx.href)
      if (url.host === this.ctx.host) {
        this.redirect(referrer)
        return
      }
    }
    this.redirect(alt || '/')
  },
}
