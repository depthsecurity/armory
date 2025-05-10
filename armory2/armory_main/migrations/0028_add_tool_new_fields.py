from django.db import migrations, models


def copy_tool_to_tool_new(apps, schema_editor):
    # Get all models that have tool_new field
    models_to_update = [
        'Basedomain', 'CIDR', 'Cred', 'CVE', 'Domain', 
        'IPAddress', 'Port', 'URL', 'User', 'Vulnerability', 'VulnOutput'
    ]
    
    for model_name in models_to_update:
        Model = apps.get_model('armory_main', model_name)
        for obj in Model.objects.all():
            if hasattr(obj, 'tool') and hasattr(obj, 'tool_new'):
                obj.tool_new = obj.tool
                obj.save()


class Migration(migrations.Migration):

    dependencies = [
        ('armory_main', '0027_change_meta_and_tools'),
    ]

    operations = [
        migrations.AddField(
            model_name='basedomain',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='cidr',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='cred',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='cve',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='domain',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='port',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='url',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='user',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='vulnoutput',
            name='tool_new',
            field=models.JSONField(default=dict),
        ),
        migrations.RunPython(
            copy_tool_to_tool_new,
            reverse_code=migrations.RunPython.noop
        ),
    ] 