from django.db import migrations, models


def copy_meta_to_meta_new(apps, schema_editor):
    # Get all models that have meta_new field
    models_to_update = [
        'Basedomain', 'CIDR', 'Cred', 'CVE', 'Domain', 
        'IPAddress', 'Port', 'URL', 'User', 'Vulnerability', 'VulnOutput'
    ]
    
    for model_name in models_to_update:
        Model = apps.get_model('armory_main', model_name)
        for obj in Model.objects.all():
            if hasattr(obj, 'meta') and hasattr(obj, 'meta_new'):
                obj.meta_new = obj.meta
                obj.save()


class Migration(migrations.Migration):

    dependencies = [
        ('armory_main', '0026_auto_20220907_1754'),
    ]

    operations = [
        migrations.AddField(
            model_name='basedomain',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='cidr',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='cred',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='cve',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='domain',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='port',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='url',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='user',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='vulnoutput',
            name='meta_new',
            field=models.JSONField(default=dict),
        ),
        migrations.RunPython(
            copy_meta_to_meta_new,
            reverse_code=migrations.RunPython.noop
        ),
    ]
