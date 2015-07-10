from django.core.urlresolvers import reverse
from ad_manager.models import ISD, AD
from django_webtest import WebTest


class BasicTestCase(WebTest):

    fixtures = ['ad_manager/tests/test_topology.json']

    def setUp(self):
        self.isds = {}
        for isd in ISD.objects.all():
            self.isds[isd.id] = isd

        self.ads = {}
        for ad in AD.objects.all():
            self.ads[ad.id] = ad

    def test_list_isds(self):
        isd_list = self.app.get(reverse('list_isds'))
        self.assertContains(isd_list, 'ISD 2')

        isd_name = 'ISD 10'
        isd_detail = isd_list.click(isd_name)
        self.assertContains(isd_detail, isd_name)

    def test_list_ads(self):
        isd = self.isds[2]
        isd_name = 'ISD 2'
        ad_list = self.app.get(reverse('isd_detail', args=[isd.id]))
        self.assertContains(ad_list, isd_name)
        self.assertNotContains(ad_list, str(self.ads[1]))

        for ad_id in [3, 4, 5]:
            ad = self.ads[ad_id]
            self.assertContains(ad_list, str(ad))

    def test_ad_detail(self):
        ad = self.ads[1]
        ad_detail = self.app.get(reverse('ad_detail', args=[ad.id]))
        self.assertContains(ad_detail, str(ad))
        html = ad_detail.html
        beacon_servers = html.find(id="beacon-servers-table")
        certificate_servers = html.find(id="certificate-servers-table")
        path_servers = html.find(id="path-servers-table")
        routers = html.find(id="routers-table")

        # Test that tables are not empty
        tables = [beacon_servers, certificate_servers, path_servers, routers]
        for table in tables:
            assert table, 'No table found'
            assert table.find('tr'), 'Table {} is empty!'.format(table)

        # Test that all beacon servers are listed
        for bs in ad.beaconserverweb_set.all():
            assert bs.addr in beacon_servers.text

        # Test that routers are listed correctly
        router_rows = routers.find_all('tr')[1:]
        for r in ad.routerweb_set.all():
            row = next(filter(lambda x: r.addr in x.text, router_rows))
            assert str(r.neighbor_ad) in row.text
            assert r.neighbor_type in row.text

        # Test that links to other ADs work
        ad_2_detail = ad_detail.click(str(self.ads[2]))
        self.assertEqual(ad_2_detail.status_int, 200)
        self.assertContains(ad_2_detail, str(self.ads[2]))
