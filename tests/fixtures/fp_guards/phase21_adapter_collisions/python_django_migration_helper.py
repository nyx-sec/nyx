from django.db import migrations


class Migration(migrations.Migration):
    operations = [
        migrations.CreateModel(name="User", fields=[]),
    ]


def normalize_name(name):
    return str(name)
