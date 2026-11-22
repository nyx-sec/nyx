# A Django migration runs from `manage.py migrate`, never from a request.
def fix_statuses_for_batch(Checkout, empty_ids):
    checkouts = Checkout.objects.filter(pk__in=empty_ids).prefetch_related("lines")
    return checkouts
