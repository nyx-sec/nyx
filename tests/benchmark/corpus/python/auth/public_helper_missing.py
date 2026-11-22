from .models import EventDelivery


# Public helper that takes caller supplied ids with no scoping.
def remove_deliveries(deliveries_ids):
    return EventDelivery.objects.filter(id__in=deliveries_ids)
