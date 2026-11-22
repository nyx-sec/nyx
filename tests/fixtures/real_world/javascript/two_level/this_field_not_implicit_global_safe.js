class Reporter {
  loadToken() {
    this.token = process.env.REPORT_TOKEN;
    return this.token;
  }

  async send(events) {
    const response = await fetch("https://reports.example.com/v0/events", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token}` },
      body: JSON.stringify(events),
    });
    return response.ok;
  }
}

module.exports = Reporter;
