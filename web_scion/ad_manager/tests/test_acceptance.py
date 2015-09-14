
# External packages
import tempfile
from django.conf import settings
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.utils import timezone
from django_webtest import WebTest
from unittest.mock import patch

# SCION
from guardian.shortcuts import assign_perm
from ad_management.util import response_success
from ad_manager.models import ISD, AD, PackageVersion, ConnectionRequest


class BasicWebTest(WebTest):

    fixtures = ['ad_manager/tests/test_topology.json']

    def setUp(self):
        super().setUp()
        self.isds = {}
        for isd in ISD.objects.all():
            self.isds[isd.id] = isd

        self.ads = {}
        for ad in AD.objects.all():
            self.ads[ad.id] = ad

    def _get_ad_detail(self, ad, *args, **kwargs):
        if isinstance(ad, AD):
            ad = ad.id
        assert isinstance(ad, int)
        return self.app.get(reverse('ad_detail', args=[ad]), *args, **kwargs)

    def _find_form_by_action(self, response, view_name, *args, **kwargs):
        if args is None:
            args = []
        url = reverse(view_name, *args, **kwargs)
        all_forms = response.forms.values()
        form = next(filter(lambda f: f.action == url, all_forms))
        return form


class BasicWebTestUsers(BasicWebTest):

    def setUp(self):
        super().setUp()
        assert not settings.ENABLED_2FA
        self._create_users()

    def _create_users(self):
        self.admin_user = User.objects.create_superuser(username='admin',
                                                        password='admin',
                                                        email='')
        self.user = User.objects.create_user(username='user1',
                                             password='user1',
                                             email='')


class TestListIsds(BasicWebTest):

    def test_list_isds(self):
        isd_name = 'ISD 2'
        isd_list = self.app.get(reverse('list_isds'))
        self.assertContains(isd_list, isd_name)

        # Click on the isd link
        isd_detail = isd_list.click(isd_name)
        self.assertContains(isd_detail, isd_name)


class TestListAds(BasicWebTest):

    def test_list_ads(self):
        isd = self.isds[2]
        isd_name = 'ISD 2'
        ad_list = self.app.get(reverse('isd_detail', args=[isd.id]))
        self.assertContains(ad_list, isd_name)
        self.assertNotContains(ad_list, str(self.ads[1]))

        for ad_id in [3, 4, 5]:
            ad = self.ads[ad_id]
            self.assertContains(ad_list, str(ad))

    def test_list_core(self):
        isd = self.isds[2]
        ad = self.ads[3]
        ad.is_core_ad = True
        ad.save()
        assert ad.isd == isd

        ad_list = self.app.get(reverse('isd_detail', args=[isd.id]))
        self.assertContains(ad_list, ad.id)
        li_tag = ad_list.html.find('a', text='AD 2-3').parent
        self.assertIn('core', li_tag.text)


class TestAdDetail(BasicWebTest):

    def test_servers_page(self):
        ad = self.ads[1]
        ad_detail = self._get_ad_detail(ad)
        self.assertContains(ad_detail, str(ad))
        html = ad_detail.html
        beacon_servers = html.find(id="beacon-servers-table")
        certificate_servers = html.find(id="certificate-servers-table")
        path_servers = html.find(id="path-servers-table")
        dns_servers = html.find(id="dns-servers-table")
        routers = html.find(id="routers-table")

        # Test that tables are not empty
        tables = [beacon_servers, certificate_servers, path_servers,
                  dns_servers, routers]
        for table in tables:
            assert table, 'No table found'
            self.assertFalse('No servers' in str(table), "Table is empty")

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

    def test_labels(self):
        ad = self.ads[1]
        value_map = {True: 'Yes', False: 'No'}

        # Test core label
        for is_core_value, page_value in value_map.items():
            ad.is_core_ad = is_core_value
            ad.save()
            ad_detail = self._get_ad_detail(ad)
            core_container = ad_detail.html.find(id='core-label')
            self.assertIn(page_value, core_container.text,
                          'Invalid label: core')

        # Test open label
        for is_open_value, page_value in value_map.items():
            ad.is_open = is_open_value
            ad.save()
            ad_detail = self._get_ad_detail(ad)
            open_container = ad_detail.html.find(id='open-label')
            self.assertIn(page_value, open_container.text,
                          'Invalid label: open')


class TestUsersAndPermissions(BasicWebTestUsers):

    CONTROL_CLASS = 'process-control-form'

    def test_login_admin(self):
        ad_detail = self._get_ad_detail(self.ads[1])
        self.assertNotContains(ad_detail, 'admin')
        login_page = ad_detail.click('Login')
        login_form = login_page.form
        login_form['username'] = 'admin'
        login_form['password'] = 'admin'
        res = login_form.submit().follow()
        self.assertContains(res, 'AD 1')
        self.assertContains(res, 'Logged in as:')
        self.assertContains(res, 'admin')

    def test_admin_panel(self):
        admin_index = reverse('admin:index')
        # Anon user
        login_page = self.app.get(admin_index).follow()
        self.assertContains(login_page, 'Username:')

        # Non-admin user
        admin_page = self.app.get(admin_index, user=self.user)
        self.assertContains(admin_page, 'Site administration')
        self.assertContains(admin_page, "You don't have permission")

        # Admin user
        admin_page = self.app.get(admin_index, user=self.admin_user)
        self.assertContains(admin_page, 'Site administration')
        self.assertContains(admin_page, 'Authentication and Authorization')

    def test_login_logout(self):
        home = self.app.get('/', user=self.user).maybe_follow()
        res = home.click('logout').maybe_follow()
        self.assertContains(res, 'Login')

    def test_nonpriv_user_control(self):
        ad = self.ads[1]
        bs = ad.beaconserverweb_set.first()
        ad_detail = self._get_ad_detail(ad)

        # No control buttons
        self.assertFalse(ad_detail.html.findAll('form', self.CONTROL_CLASS))

        # Action is forbidden
        control_url = reverse('control_process', args=[ad.id, bs.id_str()])
        res = self.app.post(control_url, expect_errors=True)
        self.assertEqual(res.status_code, 403)

    @patch("ad_manager.util.management_client.control_process")
    def test_priv_user_control(self, control_process):
        ad = self.ads[1]
        bs = ad.beaconserverweb_set.first()
        ad_detail = self._get_ad_detail(ad, user=self.admin_user)

        self.assertTrue(ad_detail.html.findAll('form', self.CONTROL_CLASS))

        # Find the bs control form
        bs_control_form = self._find_form_by_action(ad_detail,
                                                    'control_process',
                                                    args=[ad.id, bs.id_str()])

        # Press the "start" button
        control_process.return_value = response_success('ok')
        res = bs_control_form.submit('_start_process')
        self.assertTrue(res.json)


class TestPackageDownload(BasicWebTestUsers):

    def _get_download_form(self, get_args=None):
        if get_args is None:
            get_args = {}

        ad = self.ads[1]
        ad_detail = self._get_ad_detail(ad, **get_args)

        download_form = self._find_form_by_action(ad_detail, 'update_action',
                                                  args=[ad.id])
        return download_form

    def test_nonpriv_user(self):
        download_form = self._get_download_form()
        res = download_form.submit('_download_update', expect_errors=True)
        self.assertEqual(res.status_code, 403)

    def test_download(self):
        data = b'123'
        with tempfile.NamedTemporaryFile() as tmp_file:
            tmp_file.write(data)
            tmp_file.flush()

            package = PackageVersion(name='test_package',
                                     filepath=tmp_file.name,
                                     date_created=timezone.now(),
                                     size=tmp_file.tell())
            package.save()

            args = {'user': self.admin_user}
            download_form = self._get_download_form(get_args=args)
            download_form.fields['selected_version'] = package
            res = download_form.submit('_download_update').maybe_follow()
            self.assertEqual(data, res.body)


class TestConnectionRequests(BasicWebTestUsers):

    def _get_request_page(self, ad_id):
        requests_page = reverse('ad_connection_requests', args=[ad_id])
        return requests_page

    def test_view_nopriv(self):
        ad = self.ads[2]
        requests_page = self._get_request_page(ad.id)

        # Anon user
        ad_requests = self.app.get(requests_page)
        self.assertNotContains(ad_requests, 'Received requests')
        self.assertNotContains(ad_requests, 'Created by')

        # Non-priv user
        ad_requests = self.app.get(requests_page, user=self.user)
        self.assertNotContains(ad_requests, 'Received requests')
        self.assertNotContains(ad_requests, 'Created by')

    def test_priv_user(self):
        ad = self.ads[2]
        requests_page = self._get_request_page(ad.id)

        # Admin user
        ad_requests = self.app.get(requests_page, user=self.admin_user)
        self.assertContains(ad_requests, 'Received requests')

        # User which has access to the AD
        assign_perm('change_ad', self.user, ad)
        ad_requests = self.app.get(requests_page, user=self.user)
        self.assertContains(ad_requests, 'Received requests')

    def test_send_request(self):
        ad = self.ads[2]
        ad.is_open = False
        ad.save()
        requests_page = self._get_request_page(ad.id)
        sent_requests_page = reverse('sent_requests')
        self.assertEqual(len(ConnectionRequest.objects.all()), 0)

        # Fill and submit the form
        ad_requests = self.app.get(requests_page, user=self.admin_user)
        request_form = ad_requests.click('New request').maybe_follow().form
        request_form['router_bound_ip'] = '123.234.123.234'
        request_form['router_bound_port'] = 12345
        request_form['info'] = 'test info'
        request_form.submit()
        self.assertEqual(len(ConnectionRequest.objects.all()), 1)
        request = ConnectionRequest.objects.first()
        self.assertEqual(request.created_by, self.admin_user)

        # Check that the sent request is listed at the 'sent requests' page
        sent_requests = self.app.get(sent_requests_page, user=self.admin_user)
        self.assertIn('submitted by admin', sent_requests.html.text)
        sent_table = sent_requests.html.find(id="sent-requests-tbl")
        for s in [ad, '123.234.123.234', 12345, 'test info', 'SENT']:
            self.assertIn(str(s), str(sent_table))

        # Check that the request is listed in the 'received' table
        # for admins and authorized users
        assign_perm('change_ad', self.user, ad)
        ad_requests_admin = self.app.get(requests_page, user=self.admin_user)
        ad_requests_user = self.app.get(requests_page, user=self.user)
        for response in [ad_requests_admin, ad_requests_user]:
            received_table = response.html.find(id="received-requests-tbl")
            for s in ['123.234.123.234', 'test info', 'SENT', 'admin']:
                self.assertIn(str(s), str(received_table))

    def test_decline_request(self):
        ad = self.ads[2]
        ad_requests_page = self._get_request_page(ad.id)
        sent_requests_page = reverse('sent_requests')

        request = ConnectionRequest(created_by=self.user, connect_to=ad,
                                    info='test info', status='SENT',
                                    router_bound_ip='123.123.123.123')
        request.save()

        ad_requests = self.app.get(ad_requests_page, user=self.admin_user)
        self.assertContains(ad_requests, '123.123.123.123')
        sent_requests = self.app.get(sent_requests_page, user=self.user)
        self.assertContains(sent_requests, '123.123.123.123')

        control_form = self._find_form_by_action(ad_requests,
                                                 'connection_request_action',
                                                 args=[request.id])
        ad_requests = control_form.submit('_decline_request',
                                          user=self.admin_user).maybe_follow()
        self.assertContains(ad_requests, 'DECLINED')
        sent_requests = self.app.get(sent_requests_page, user=self.user)
        self.assertContains(sent_requests, 'DECLINED')

        # Check that it's impossible to download the package
        download_url = reverse('download_request_package', args=[request.id])
        resp = self.app.get(download_url, expect_errors=True)
        self.assertEqual(resp.status_int, 403)
        self.assertIsNone(request.package_path)


class TestNewLink(BasicWebTestUsers):

    def test_permissions(self):
        ad = self.ads[2]
        new_link_page = reverse('new_link', args=[ad.id])
        resp = self.app.get(new_link_page, user=self.admin_user)
        self.assertContains(resp, 'Link type')

        resp = self.app.get(new_link_page, user=self.user, expect_errors=True)
        self.assertEqual(resp.status_code, 403)
