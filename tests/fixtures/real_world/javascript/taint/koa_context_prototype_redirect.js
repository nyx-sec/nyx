// Koa's own response prototype: it never imports koa, and reads the
// Referrer header through `this.ctx.get`.
module.exports = {
  redirect(url) {
    this.set('Location', url)
    this.status = 302
  },

  // The Referrer header decides where the browser goes next.
  back(alt) {
    const referrer = this.ctx.get('Referrer')
    this.redirect(referrer || alt || '/')
  },
}
