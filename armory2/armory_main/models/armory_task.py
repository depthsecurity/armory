from django.db import models



class ArmoryTask(models.Model):

    name = models.CharField(max_length=64)
    started = models.DateTimeField(auto_now_add=True)
    finished = models.BooleanField(default=False)
    command = models.TextField()
    logfile = models.CharField(max_length=256)
    module = models.CharField(max_length=128)
