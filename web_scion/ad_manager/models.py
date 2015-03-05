from django.db import models


class ISD(models.Model):
    id = models.CharField(max_length=50, primary_key=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name = 'ISD'


class AD(models.Model):
    id = models.CharField(max_length=50, primary_key=True)
    isd = models.ForeignKey('ISD')
    is_core_ad = models.BooleanField(default=False)

    def __str__(self):
        return '{}:{}'.format(self.isd.id, self.id)

    class Meta:
        verbose_name = 'AD'


class SCIONWebElement(models.Model):
    addr = models.IPAddressField()
    ad = models.ForeignKey(AD)

    def save(self, *args, **kwargs):
        if getattr(self, '_image_changed', True):
            pass
        super(SCIONWebElement, self).save(*args, **kwargs)

    def __str__(self):
        return '{} -- {}'.format(self.ad, self.addr)

    class Meta:
        abstract = True


class BeaconServerWeb(SCIONWebElement):
    class Meta:
        verbose_name = 'Beacon server'
        unique_together = (("ad", "addr"),)


class CertificateServerWeb(SCIONWebElement):
    class Meta:
        verbose_name = 'Certificate server'
        unique_together = (("ad", "addr"),)


class PathServerWeb(SCIONWebElement):
    class Meta:
        verbose_name = 'Path server'
        unique_together = (("ad", "addr"),)


class RouterWeb(SCIONWebElement):
    class Meta:
        verbose_name = 'Router'
        unique_together = (("ad", "addr"),)
