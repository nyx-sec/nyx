import pika


class ReportWorker:
    def process(self, report):
        return {"status": "queued", "report_id": report.get("id")}


worker = ReportWorker()


def process(report):
    return worker.process(report)
