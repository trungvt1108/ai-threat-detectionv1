"""Before this change, create_experiment advanced DetectionCheckpoint for dataset
namespaces (ds:...), so a later `detect` on that dataset skipped every window.
Experiments now build windows without a checkpoint. This removes checkpoints in
ds: namespaces where detection never produced anything (no rule/ML decision and
no alert), i.e. checkpoints that only an experiment created. Windows are kept;
detection will reuse them.
"""

from django.db import migrations


def forwards(apps, schema_editor):
    DetectionCheckpoint = apps.get_model("atd_features", "DetectionCheckpoint")
    RuleDecision = apps.get_model("atd_rules", "RuleDecision")
    MLDecision = apps.get_model("atd_registry", "MLDecision")
    Alert = apps.get_model("atd_alerts", "Alert")
    for cp in DetectionCheckpoint.objects.filter(namespace__startswith="ds:"):
        used = (
            RuleDecision.objects.filter(namespace=cp.namespace, domain=cp.domain).exists()
            or MLDecision.objects.filter(window__namespace=cp.namespace, window__domain=cp.domain).exists()
            or Alert.objects.filter(namespace=cp.namespace, domain=cp.domain).exists()
        )
        if not used:
            cp.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("atd_features", "0001_initial"),
        ("atd_rules", "0001_initial"),
        ("atd_registry", "0001_initial"),
        ("atd_alerts", "0001_initial"),
    ]

    operations = [migrations.RunPython(forwards, migrations.RunPython.noop)]
