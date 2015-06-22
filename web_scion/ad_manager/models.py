# Stdlib
import glob
import json
import os
import tarfile

# External packages
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
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
)
from lib.topology import Topology
from topology.generator import PORT


class SelectRelatedModelManager(models.Manager):
    """
    Model manager that also selects related objects from the database,
    avoiding multiple similar queries.
    """

    def __init__(self, *args):
        super(SelectRelatedModelManager, self).__init__()
        self.related_fields = args

    def get_queryset(self):
        queryset = super(SelectRelatedModelManager, self).get_queryset()
        return queryset.select_related(*self.related_fields)


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

    # Use custom model manager with select_related()
    objects = SelectRelatedModelManager('isd')

    def get_monitoring_daemon_host(self):
        """
        Return the host where the monitoring daemon is running.
        """
        monitoring_daemon_host = '127.0.0.1'
        beacon_server = self.beaconserverweb_set.first()
        # TODO fix the check for private addresses
        if beacon_server and not beacon_server.addr.startswith('127.'):
            monitoring_daemon_host = beacon_server.addr
        return monitoring_daemon_host

    def query_ad_status(self):
        """
        Return AD status information, which includes servers/routers statuses
        """
        return monitoring_client.get_ad_info(self.get_monitoring_daemon_host(),
                                             self.isd_id, self.id)

    def get_remote_topology(self):
        """
        Get the corresponding remote topology as a Python dictionary.
        """
        md_host = self.get_monitoring_daemon_host()
        topology_response = monitoring_client.get_topology(md_host,
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
        out_dict = {
            'ISDID': int(self.isd_id), 'ADID': int(self.id),
            'Core': int(self.is_core_ad), 'DnsDomain': self.dns_domain,
            'EdgeRouters': {}, 'PathServers': {}, 'BeaconServers': {},
            'CertificateServers': {}, 'DNSServers': {},
        }
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

    def fill_from_topology(self, topology, clear=False):
        """
        Add infrastructure elements (servers, routers) to the AD, extracted
        from the Topology object.
        """
        assert isinstance(topology, Topology), 'Topology object expected'

        if clear:
            self.routerweb_set.all().delete()
            self.pathserverweb_set.all().delete()
            self.certificateserverweb_set.all().delete()
            self.beaconserverweb_set.all().delete()
            self.dnsserverweb_set.all().delete()

        self.is_core_ad = topology.is_core_ad
        self.dns_domain = topology.dns_domain
        self.save()

        routers = topology.get_all_edge_routers()
        beacon_servers = topology.beacon_servers
        certificate_servers = topology.certificate_servers
        path_servers = topology.path_servers
        dns_servers = topology.dns_servers

        try:
            for router in routers:
                interface = router.interface
                neighbor_ad = AD.objects.get(id=interface.neighbor_ad,
                                             isd=interface.neighbor_isd)
                router_element = RouterWeb(
                    addr=str(router.addr), ad=self,
                    name=router.name, neighbor_ad=neighbor_ad,
                    neighbor_type=interface.neighbor_type,
                    interface_addr=str(interface.addr),
                    interface_toaddr=str(interface.to_addr),
                    interface_id=interface.if_id
                )
                router_element.save()

            for bs in beacon_servers:
                bs_element = BeaconServerWeb(addr=str(bs.addr),
                                             name=bs.name,
                                             ad=self)
                bs_element.save()

            for cs in certificate_servers:
                cs_element = CertificateServerWeb(addr=str(cs.addr),
                                                  name=cs.name,
                                                  ad=self)
                cs_element.save()

            for ps in path_servers:
                ps_element = PathServerWeb(addr=str(ps.addr),
                                           name=ps.name,
                                           ad=self)
                ps_element.save()

            for ds in dns_servers:
                ds_element = DnsServerWeb(addr=str(ds.addr),
                                          name=ds.name,
                                          ad=self)
                ds_element.save()
        except IntegrityError:
            pass

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

    interface_addr = models.GenericIPAddressField()
    interface_toaddr = models.GenericIPAddressField()
    interface_id = models.IntegerField()
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

    def is_approved(self):
        return self.status == 'APPROVED'
