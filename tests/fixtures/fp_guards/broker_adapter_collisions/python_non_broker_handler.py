import boto3


sqs = boto3.client("sqs")


class AuditCache:
    def process_message(self, envelope):
        return {"stored": True, "id": envelope.get("id")}


cache = AuditCache()


def handler(envelope):
    return cache.process_message(envelope)
