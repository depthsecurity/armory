from django.db import models


class Tag(models.Model):
    TYPE_IP = 'ip'
    TYPE_DOMAIN = 'domain'
    TYPE_CRED = 'cred'
    TYPE_ANY = 'any'

    TYPE_CHOICES = [
        (TYPE_IP, 'IP'),
        (TYPE_DOMAIN, 'Domain'),
        (TYPE_CRED, 'Credential'),
        (TYPE_ANY, 'Any'),
    ]

    name = models.CharField(max_length=128, unique=True)
    type = models.CharField(max_length=16, choices=TYPE_CHOICES, default=TYPE_ANY)

    def __str__(self):
        return f"{self.name} ({self.type})"

    class Meta:
        ordering = ['name']
