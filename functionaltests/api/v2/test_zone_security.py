from tempest_lib.exceptions import BadRequest
from tempest_lib.exceptions import InvalidContentType
from tempest_lib.exceptions import ServerFault

from functionaltests.common import utils
from functionaltests.api.v2 import security_utils
from functionaltests.common import datagen
from functionaltests.api.v2.base import DesignateV2Test
from functionaltests.api.v2.clients.zone_client import ZoneClient
from functionaltests.api.v2.clients.zone_import_client import ZoneImportClient

import urllib

fuzzer = security_utils.Fuzzer()


@utils.parameterized_class
class ZoneFuzzTest(DesignateV2Test):

    def setUp(self):
        super(ZoneFuzzTest, self).setUp()
        self.client = ZoneClient.as_user('default')
        self.increase_quotas(user='default')

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_fuzz_name(self, fuzz_type, payload):
        test_model = datagen.random_zone_data()
        test_model.name = payload
        fuzzer.verify_exception(
            self.client.post_zone, BadRequest, fuzz_type, test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_fuzz_email(self, fuzz_type, payload):
        test_model = datagen.random_zone_data()
        test_model.email = payload
        fuzzer.verify_exception(
            self.client.post_zone, BadRequest, fuzz_type, test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_fuzz_description(self, fuzz_type, payload):
        test_model = datagen.random_zone_data()
        test_model.description = payload
        fuzzer.verify_exception(
            self.client.post_zone, BadRequest, fuzz_type, test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_fuzz_ttl(self, fuzz_type, payload):
        test_model = datagen.random_zone_data()
        test_model.ttl = payload
        fuzzer.verify_exception(
            self.client.post_zone, BadRequest, fuzz_type, test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_fuzz_masters(self, fuzz_type, payload):
        test_model = datagen.random_zone_data()
        test_model.masters = payload
        fuzzer.verify_exception(
            self.client.post_zone, BadRequest, fuzz_type, test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_fuzz_content_type_header(self, fuzz_type, payload):
        test_model = datagen.random_zone_data()
        headers = {"Content-Type": payload.encode('utf-8')}
        fuzzer.verify_exception(
            self.client.post_zone, InvalidContentType, fuzz_type, test_model,
            headers=headers)

    # @utils.parameterized(fuzzer.get_datasets(
    #     ['content_types', 'junk', 'sqli', 'xss', 'rce']
    # ))
    # def test_create_zone_fuzz_accept_header(self, fuzz_type, payload):
    #     test_model = datagen.random_zone_data()
    #     headers = {"accept": payload.encode('utf-8')}
    #     fuzzer.verify_exception(
    #         self.client.post_zone, InvalidContentType, fuzz_type, test_model,
    #         headers=headers)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_zone_fuzz_name(self, fuzz_type, payload):
        resp, old_model = self._create_zone(
                                        datagen.random_zone_data())

        test_model = datagen.random_zone_data()
        test_model.name = payload

        fuzzer.verify_exception(
            self.client.patch_zone, BadRequest, fuzz_type, old_model.id,
            test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_zone_fuzz_email(self, fuzz_type, payload):
        resp, old_model = self._create_zone(
                                        datagen.random_zone_data())

        test_model = datagen.random_zone_data()
        test_model.email = payload

        fuzzer.verify_exception(
            self.client.patch_zone, BadRequest, fuzz_type, old_model.id,
            test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_zone_fuzz_description(self, fuzz_type, payload):
        resp, old_model = self._create_zone(
                                        datagen.random_zone_data())

        test_model = datagen.random_zone_data()
        test_model.description = payload

        fuzzer.verify_exception(
            self.client.patch_zone, BadRequest, fuzz_type, old_model.id,
            test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_zone_fuzz_ttl(self, fuzz_type, payload):
        resp, old_model = self._create_zone(
                                        datagen.random_zone_data())

        test_model = datagen.random_zone_data()
        test_model.ttl = payload

        fuzzer.verify_exception(
            self.client.patch_zone, BadRequest, fuzz_type, old_model.id,
            test_model)

    @utils.parameterized(fuzzer.get_datasets(
        ['content_types', 'bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_zone_fuzz_header(self, fuzz_type, payload):
        test_resp, test_model = self._create_zone(
                                        datagen.random_zone_data())
        headers = {"Accept": payload}
        fuzzer.verify_exception(
            self.client.get_zone, InvalidContentType, fuzz_type, test_model.id,
            headers=headers)

    """
    FAILING: 500
    """
    @utils.parameterized(fuzzer.get_datasets(
        ['bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_zone_nameservers_fuzz_uuid(self, fuzz_type, payload):
        # client = ZoneClient.as_user('default').client
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))
        fuzzer.verify_exception(
            self.client.client.get, ServerFault, fuzz_type,
            url='/v2/zones/{0}/nameservers'.format(payload))

    @utils.parameterized(fuzzer.get_datasets(
        ['bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_abandon_zone_fuzz_uuid(self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))
        fuzzer.verify_exception(
            self.client.client.post, BadRequest, fuzz_type,
            url='/v2/zones/{0}/tasks/abandon'.format(payload), body='')

    @utils.parameterized(fuzzer.get_datasets(
        ['bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_transfer_fuzz_uuid(self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))

        fuzzer.verify_exception(
            self.client.client.post, BadRequest, fuzz_type,
            url='/v2/zones/{0}/tasks/transfer_requests'.format(payload),
            body='')

    @utils.parameterized(fuzzer.get_datasets(
        ['bad_numbers', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_list_zones_fuzz_limit_filter(self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))

        fuzzer.verify_exception(
            self.client.client.post, BadRequest, fuzz_type,
            url='/v2/zones?limit={0}'.format(payload),
            body='')

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_list_zones_fuzz_sort_key_filter(self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))

        fuzzer.verify_exception(
            self.client.client.post, BadRequest, fuzz_type,
            url='/v2/zones?sort_key={0}'.format(payload),
            body='')

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_list_zones_fuzz_marker_filter(self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))

        fuzzer.verify_exception(
            self.client.client.post, BadRequest, fuzz_type,
            url='/v2/zones?marker={0}'.format(payload),
            body='')

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_list_zones_fuzz_sort_dir_filter(self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))

        fuzzer.verify_exception(
            self.client.client.post, BadRequest, fuzz_type,
            url='/v2/zones?sort_dir={0}'.format(payload),
            body='')

    def _create_zone(self, zone_model, user='default'):
        resp, model = ZoneClient.as_user(user).post_zone(zone_model)
        self.assertEqual(resp.status, 202)
        ZoneClient.as_user(user).wait_for_zone(model.id)
        return resp, model


@utils.parameterized_class
class ZoneImportFuzzTest(DesignateV2Test):

    def setUp(self):
        super(ZoneImportFuzzTest, self).setUp()
        self.client = ZoneImportClient.as_user('default')
        self.increase_quotas(user='default')

    #
    # post_zone_import got multiple values for 'headers'
    # **TODO: mcdong change client?**
    #
    @utils.parameterized(fuzzer.get_datasets(
        ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_import_fuzz_content_type_header(
            self, fuzz_type, payload):
        zonefile = datagen.random_zonefile_data()
        headers = {"Content-Type": payload.encode('utf-8')}
        fuzzer.verify_exception(
            self.client.post_zone_import, InvalidContentType,
            fuzz_type, zonefile, headers=headers)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_import_fuzz_name(
            self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
                payload = urllib.quote_plus(payload.encode('utf-8'))
        zonefile = datagen.random_zonefile_data(name=payload)
        fuzzer.verify_exception(
            self.client.post_zone_import, BadRequest,
            fuzz_type, zonefile)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_import_fuzz_ttl(
            self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))
        zonefile = datagen.random_zonefile_data(ttl=payload)
        fuzzer.verify_exception(
            self.client.post_zone_import, BadRequest,
            fuzz_type, zonefile)

    @utils.parameterized(fuzzer.get_datasets(
        ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_view_zone_import_fuzz_accept_type_header(
            self, fuzz_type, payload):
        zonefile = datagen.random_zonefile_data()
        resp, model = self.client.post_zone_import(
            zonefile)
        self.client.wait_for_zone_import(model.id)

        headers = {"accept": payload.encode('utf-8')}
        fuzzer.verify_exception(
            self.client.get_zone_import, InvalidContentType,
            fuzz_type, model.id, headers=headers)
