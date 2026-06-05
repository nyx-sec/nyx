from celery import shared_task


@shared_task
def tick(payload):
    return payload


class Mailer:
    def delay(self, payload):
        return payload


def enqueue(payload):
    mailer = Mailer()
    return mailer.delay(payload)
