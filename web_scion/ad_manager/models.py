# Stdlib
import glob
import json
import os
import tarfile

# External packages
from django.db import models, IntegrityError

# SCION
from ad_management.common import (
    get_success_data,
    is_success,
    PACKAGE_DIR_PATH,
)
from ad_manager.util import monitoring_client
from lib.topology import Topology
from topology.generator import PORT, ConfigGenerator


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

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name = 'ISD'


class AD(models.Model):
    id = models.AutoField(primary_key=True)
    isd = models.ForeignKey('ISD')
    is_core_ad = models.BooleanField(default=False)

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
        return monitoring_client.get_ad_info(self.isd_id, self.id,
                                             self.get_monitoring_daemon_host())

    def get_remote_topology(self):
        """
        Get the corresponding remote topology as a Python dictionary.
        """
        md_host = self.get_monitoring_daemon_host()
        topology_response = monitoring_client.get_topology(self.isd.id, self.id,
                                                           md_host)
        if not is_success(topology_response):
            return None

        topology_str = get_success_data(topology_response)
        try:
            topology_dict = json.loads(topology_str)
            return topology_dict
        except ValueError:
            return None

    def generate_topology_dict(self):
        """
        Create a Python dictionary with the stored AD topology.
        """
        out_dict = {
            'ISDID': int(self.isd_id), 'ADID': int(self.id),
            'Core': int(self.is_core_ad),
            'EdgeRouters': {}, 'PathServers': {}, 'BeaconServers': {},
            'CertificateServers': {},
        }
        for i, router in enumerate(self.routerweb_set.all(), start=1):
            out_dict['EdgeRouters'][str(i)] = router.get_dict()
        for i, ps in enumerate(self.pathserverweb_set.all(), start=1):
            out_dict['PathServers'][str(i)] = ps.get_dict()
        for i, bs in enumerate(self.beaconserverweb_set.all(), start=1):
            out_dict['BeaconServers'][str(i)] = bs.get_dict()
        for i, cs in enumerate(self.certificateserverweb_set.all(), start=1):
            out_dict['CertificateServers'][str(i)] = cs.get_dict()
        return out_dict

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

        self.is_core_ad = topology.is_core_ad

        routers = topology.get_all_edge_routers()
        beacon_servers = topology.beacon_servers
        certificate_servers = topology.certificate_servers
        path_servers = topology.path_servers

        try:
            for router in routers:
                interface = router.interface
                neighbor_ad = AD.objects.get(id=interface.neighbor_ad,
                                             isd=interface.neighbor_isd)
                router_element = RouterWeb(
                    addr=router.addr, ad=self,
                    neighbor_ad=neighbor_ad,
                    neighbor_type=interface.neighbor_type,
                    interface_addr=interface.addr,
                    interface_toaddr=interface.to_addr,
                    interface_id=interface.if_id
                )
                router_element.save()

            for bs in beacon_servers:
                bs_element = BeaconServerWeb(addr=bs.addr, ad=self)
                bs_element.save()

            for cs in certificate_servers:
                cs_element = CertificateServerWeb(addr=cs.addr, ad=self)
                cs_element.save()

            for ps in path_servers:
                ps_element = PathServerWeb(addr=ps.addr, ad=self)
                ps_element.save()
        except IntegrityError:
            pass

    def __str__(self):
        return '{}-{}'.format(self.isd.id, self.id)

    class Meta:
        verbose_name = 'AD'


class SCIONWebElement(models.Model):
    addr = models.IPAddressField()
    ad = models.ForeignKey(AD)

    def id_str(self):
        # FIXME How to identify multiple servers of the same type?
        return "{}{}-{}-1".format(self.prefix, self.ad.isd_id, self.ad_id)

    def get_dict(self):
        return {'AddrType': 'IPv4', 'Addr': self.addr}

    def __str__(self):
        return '{} -- {}'.format(self.ad, self.addr)

    class Meta:
        abstract = True


class BeaconServerWeb(SCIONWebElement):
    prefix = 'bs'

    class Meta:
        verbose_name = 'Beacon server'
        unique_together = (("ad", "addr"),)


class CertificateServerWeb(SCIONWebElement):
    prefix = 'cs'

    class Meta:
        verbose_name = 'Certificate server'
        unique_together = (("ad", "addr"),)


class PathServerWeb(SCIONWebElement):
    prefix = 'ps'

    class Meta:
        verbose_name = 'Path server'
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

    interface_addr = models.IPAddressField()
    interface_toaddr = models.IPAddressField()
    interface_id = models.IntegerField()

    def id_str(self):
        return "er{}-{}er{}-{}".format(self.ad.isd_id, self.ad_id,
                                       self.neighbor_ad.isd_id,
                                       self.neighbor_ad.id)

    def get_dict(self):
        out_dict = super(RouterWeb, self).get_dict()
        port = int(PORT)
        if_id = ConfigGenerator.generate_if_id(self.ad_id, self.neighbor_ad_id)
        out_dict['Interface'] = {'NeighborType': self.neighbor_type,
                                 'NeighborISD': int(self.neighbor_ad.isd_id),
                                 'NeighborAD': int(self.neighbor_ad.id),
                                 'Addr': str(self.interface_addr),
                                 'AddrType': 'IPv4',
                                 'ToAddr': str(self.interface_toaddr),
                                 'UdpPort': port,
                                 'ToUdpPort': port,
                                 'IFID': if_id,
                                 }
        return out_dict

    class Meta:
        verbose_name = 'Router'
        unique_together = (("ad", "addr"),)


class PackageVersion(models.Model):
    name = models.CharField(max_length=50, null=False)
    date_created = models.DateTimeField(null=False)
    size = models.IntegerField(null=False)
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

                except (KeyError, ValueError) as ex:
                    pass

    def exists(self):
        return os.path.isfile(self.filepath)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Package version'
