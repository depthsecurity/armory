from django.db import models


class ExportQueue(models.Model):
    data = models.JSONField(default=dict)
    processed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"ExportQueue #{self.id} ({'processed' if self.processed else 'pending'})"
