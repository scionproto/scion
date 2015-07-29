# Stdlib
import copy
import glob
import json
import logging
import os
import tarfile

# External packages
import jsonfield
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db import models, IntegrityError

# SCION
from ad_management.common import (
    get_success_data,
    is_success,
    PACKAGE_DIR_PATH,
)
from ad_manager.util import monitoring_client
from ad_manager.util.common import empty_dict
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
)
from topology.generator import PORT


class SelectRelatedModelManager(models.Manager):
    """
    Model manager that also selects related objects from the database,
    avoiding multiple similar queries.
    """

    def get_queryset(self):
        queryset = super(SelectRelatedModelManager, self).get_queryset()
        related_fields = getattr(self.model, 'related_fields', [])
        if not related_fields:
            return queryset.select_related()
        else:
            return queryset.select_related(*related_fields)


class ISD(models.Model):
    id = models.IntegerField(primary_key=True)

    def get_absolute_url(self):
        return reverse('isd_detail', args=[self.id])

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name = 'ISD'
        ordering = ['id']


class AD(models.Model):
    id = models.AutoField(primary_key=True)
    isd = models.ForeignKey('ISD')
    is_core_ad = models.BooleanField(default=False)
    is_open = models.BooleanField(default=True)
    dns_domain = models.CharField(max_length=100, null=True, blank=True)
    md_host = models.IPAddressField(default='127.0.0.1')
    original_topology = jsonfield.JSONField(default=empty_dict)

    # Use custom model manager with select_related()
    objects = SelectRelatedModelManager()

    def query_ad_status(self):
        """
        Return AD status information, which includes servers/routers statuses
        """
        return monitoring_client.get_ad_info(self.md_host, self.isd_id, self.id)

    def get_remote_topology(self):
        """
        Get the corresponding remote topology as a Python dictionary.
        """
        topology_response = monitoring_client.get_topology(self.md_host,
                                                           self.isd.id, self.id)
        if not is_success(topology_response):
            return None

        topology_str = get_success_data(topology_response)
        try:
            topology_dict = json.loads(topology_str)
            return topology_dict
        except (ValueError, TypeError):
            return None

    def generate_topology_dict(self):
        """
        Create a Python dictionary with the stored AD topology.
        """
        assert isinstance(self.original_topology, dict)
        out_dict = copy.deepcopy(self.original_topology)
        out_dict.update({
            'ISDID': int(self.isd_id), 'ADID': int(self.id),
            'Core': int(self.is_core_ad), 'DnsDomain': self.dns_domain,
            'EdgeRouters': {}, 'PathServers': {}, 'BeaconServers': {},
            'CertificateServers': {}, 'DNSServers': {},
        })
        for router in self.routerweb_set.all():
            out_dict['EdgeRouters'][str(router.name)] = router.get_dict()
        for ps in self.pathserverweb_set.all():
            out_dict['PathServers'][str(ps.name)] = ps.get_dict()
        for bs in self.beaconserverweb_set.all():
            out_dict['BeaconServers'][str(bs.name)] = bs.get_dict()
        for cs in self.certificateserverweb_set.all():
            out_dict['CertificateServers'][str(cs.name)] = cs.get_dict()
        for ds in self.dnsserverweb_set.all():
            out_dict['DNSServers'][str(ds.name)] = ds.get_dict()
        return out_dict

    def get_all_elements(self):
        elements = [self.routerweb_set.all(),
                    self.pathserverweb_set.all(),
                    self.beaconserverweb_set.all(),
                    self.certificateserverweb_set.all(),
                    self.dnsserverweb_set.all()]
        for element_group in elements:
            for element in element_group:
                yield element

    def get_all_element_ids(self):
        all_elements = self.get_all_elements()
        element_ids = [element.id_str() for element in all_elements]
        return element_ids

    def fill_from_topology(self, topology_dict, clear=False):
        """
        Add infrastructure elements (servers, routers) to the AD, extracted
        from the topology dictionary.
        """
        assert isinstance(topology_dict, dict), 'Dictionary expected'

        if clear:
            self.routerweb_set.all().delete()
            self.pathserverweb_set.all().delete()
            self.certificateserverweb_set.all().delete()
            self.beaconserverweb_set.all().delete()
            self.dnsserverweb_set.all().delete()

        self.original_topology = topology_dict
        self.is_core_ad = (topology_dict['Core'] == 1)
        self.dns_domain = topology_dict['DnsDomain']
        self.save()

        routers = topology_dict["EdgeRouters"]
        beacon_servers = topology_dict["BeaconServers"]
        certificate_servers = topology_dict["CertificateServers"]
        path_servers = topology_dict["PathServers"]
        dns_servers = topology_dict["DNSServers"]

        try:
            for name, router in routers.items():
                interface = router["Interface"]
                neighbor_ad = AD.objects.get(id=interface["NeighborAD"],
                                             isd=interface["NeighborISD"])
                RouterWeb.objects.create(
                    addr=router["Addr"], ad=self,
                    name=name, neighbor_ad=neighbor_ad,
                    neighbor_type=interface["NeighborType"],
                    interface_addr=interface["Addr"],
                    interface_toaddr=interface["ToAddr"],
                    interface_id=interface["IFID"],
                    interface_port=interface["UdpPort"],
                    interface_toport=interface["ToUdpPort"],
                )

            for name, bs in beacon_servers.items():
                BeaconServerWeb.objects.create(addr=bs["Addr"],
                                               name=name,
                                               ad=self)

            for name, cs in certificate_servers.items():
                CertificateServerWeb.objects.create(addr=cs["Addr"],
                                                    name=name,
                                                    ad=self)

            for name, ps in path_servers.items():
                PathServerWeb.objects.create(addr=ps["Addr"],
                                             name=name,
                                             ad=self)

            for name, ds in dns_servers.items():
                DnsServerWeb.objects.create(addr=str(ds["Addr"]),
                                            name=name,
                                            ad=self)
        except IntegrityError:
            logging.warning("Integrity error in AD.fill_from_topology(): "
                            "ignoring")
            raise

    def get_absolute_url(self):
        return reverse('ad_detail', args=[self.id])

    def get_full_process_name(self, id_str):
        if ':' in id_str:
            return id_str
        else:
            return "ad{}-{}:{}".format(self.isd.id, self.id, id_str)

    def __str__(self):
        return '{}-{}'.format(self.isd.id, self.id)

    class Meta:
        verbose_name = 'AD'
        ordering = ['id']


class SCIONWebElement(models.Model):
    addr = models.GenericIPAddressField()
    ad = models.ForeignKey(AD)
    name = models.CharField(max_length=20, null=True)

    def id_str(self):
        # FIXME How to identify multiple servers of the same type?
        return "{}{}-{}-{}".format(self.prefix, self.ad.isd_id,
                                   self.ad_id, self.name)

    def get_dict(self):
        return {'AddrType': 'IPv4', 'Addr': self.addr}

    def __str__(self):
        return '{} -- {}'.format(self.ad, self.addr)

    class Meta:
        abstract = True


class BeaconServerWeb(SCIONWebElement):
    prefix = BEACON_SERVICE

    class Meta:
        verbose_name = 'Beacon server'
        unique_together = (("ad", "addr"),)


class CertificateServerWeb(SCIONWebElement):
    prefix = CERTIFICATE_SERVICE

    class Meta:
        verbose_name = 'Certificate server'
        unique_together = (("ad", "addr"),)


class PathServerWeb(SCIONWebElement):
    prefix = PATH_SERVICE

    class Meta:
        verbose_name = 'Path server'
        unique_together = (("ad", "addr"),)


class DnsServerWeb(SCIONWebElement):
    prefix = DNS_SERVICE

    class Meta:
        verbose_name = 'DNS server'
        unique_together = (("ad", "addr"),)


class RouterWeb(SCIONWebElement):
    NEIGHBOR_TYPES = (
        ('CHILD',) * 2,
        ('PARENT',) * 2,
        ('PEER',) * 2,
        ('ROUTING',) * 2,
    )

    neighbor_ad = models.ForeignKey(AD, related_name='neighbors')
    neighbor_type = models.CharField(max_length=10, choices=NEIGHBOR_TYPES)

    interface_id = models.IntegerField()
    interface_addr = models.GenericIPAddressField()
    interface_toaddr = models.GenericIPAddressField()
    interface_port = models.IntegerField(default=int(PORT))
    interface_toport = models.IntegerField(default=int(PORT))

    def id_str(self):
        return "er{}-{}er{}-{}".format(self.ad.isd_id, self.ad_id,
                                       self.neighbor_ad.isd_id,
                                       self.neighbor_ad.id)

    def get_dict(self):
        out_dict = super(RouterWeb, self).get_dict()
        out_dict['Interface'] = {'NeighborType': self.neighbor_type,
                                 'NeighborISD': int(self.neighbor_ad.isd_id),
                                 'NeighborAD': int(self.neighbor_ad.id),
                                 'Addr': str(self.interface_addr),
                                 'AddrType': 'IPv4',
                                 'ToAddr': str(self.interface_toaddr),
                                 'UdpPort': self.interface_port,
                                 'ToUdpPort': self.interface_toport,
                                 'IFID': self.interface_id,
                                 }
        return out_dict

    class Meta:
        verbose_name = 'Router'
        unique_together = (("ad", "addr"),)


class PackageVersion(models.Model):
    name = models.CharField(max_length=50, null=False)
    date_created = models.DateTimeField(null=False)
    size = models.IntegerField(null=False)
    # TODO change to FilePathField?
    filepath = models.CharField(max_length=400, null=False)

    @staticmethod
    def discover_packages(clear=True):
        if clear:
            PackageVersion.objects.all().delete()

        glob_string = os.path.join(PACKAGE_DIR_PATH, '*.tar')
        tar_files = glob.glob(glob_string)
        for filename in tar_files:
            with tarfile.open(filename, 'r') as tar_fh:
                try:
                    # Check metadata
                    metadata_tarinfo = tar_fh.getmember('META')
                    metadata_file = tar_fh.extractfile(metadata_tarinfo)
                    metadata_string = str(metadata_file.read(), 'utf8')
                    metadata = json.loads(metadata_string)
                    package_name = os.path.basename(filename)
                    package_path = os.path.abspath(filename)
                    package_version = PackageVersion(
                        name=package_name,
                        date_created=metadata['date'],
                        size=os.path.getsize(filename),
                        filepath=package_path,
                    )
                    package_version.save()

                except (KeyError, ValueError):
                    pass

    def exists(self):
        return os.path.isfile(self.filepath)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Package version'


class ConnectionRequest(models.Model):

    STATUS_OPTIONS = ['NONE', 'SENT', 'APPROVED', 'DECLINED']

    created_by = models.ForeignKey(User)
    connect_to = models.ForeignKey(AD, related_name='received_requests')
    new_ad = models.ForeignKey(AD, blank=True, null=True)
    info = models.TextField()
    router_bound_ip = models.GenericIPAddressField()
    router_bound_port = models.IntegerField(default=int(PORT))
    router_public_ip = models.GenericIPAddressField(blank=True, null=True)
    router_public_port = models.IntegerField(blank=True, null=True)
    status = models.CharField(max_length=20,
                              choices=zip(STATUS_OPTIONS, STATUS_OPTIONS),
                              default='NONE')
    # TODO change to FilePathField?
    package_path = models.CharField(max_length=1000, blank=True, null=True)

    related_fields = ('new_ad__isd', 'connect_to__isd', 'created_by')
    objects = SelectRelatedModelManager()

    def is_approved(self):
        return self.status == 'APPROVED'
