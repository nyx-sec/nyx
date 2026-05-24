const { SQSClient } = require("@aws-sdk/client-sqs");

class MetricsPublisher {
    send(event) {
        return Promise.resolve({ ok: true, event });
    }
}

const sqs = new SQSClient({});
const metrics = new MetricsPublisher();

function handler(event) {
    return metrics.send({
        type: "delivery_attempt",
        requestId: event.requestId,
    });
}

module.exports = { handler, sqs };
