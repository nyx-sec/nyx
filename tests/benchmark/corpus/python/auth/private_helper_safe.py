from .models import EventDelivery


# Module-private helper: the ids come from its caller, not from a request.
def _raw_remove_deliveries(deliveries_ids):
    return EventDelivery.objects.filter(id__in=deliveries_ids)


def purge_task(batch):
    return _raw_remove_deliveries(batch)
