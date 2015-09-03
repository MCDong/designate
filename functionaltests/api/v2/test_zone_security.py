from functionaltests.common import utils
from functionaltests.api.v2.security_utils import FuzzFactory
from functionaltests.common import datagen
from functionaltests.api.v2.base import DesignateV2Test
from functionaltests.api.v2.clients.zone_client import ZoneClient
from functionaltests.api.v2.clients.zone_import_client import ZoneImportClient
from six import string_types
from six.moves.urllib.parse import quote_plus

import urllib

fuzzer = FuzzFactory()


@utils.parameterized_class
class ZoneFuzzTest(DesignateV2Test):

    def setUp(self):
        super(ZoneFuzzTest, self).setUp()
        self.client = ZoneClient.as_user('default')
        self.increase_quotas(user='default')

    zone_params = [
        'description', 'name', 'type', 'email', 'ttl', 'masters'
    ]

    @utils.parameterized(fuzzer.get_param_datasets(
        zone_params, ['junk', 'sqli', 'xss', 'rce', 'huge']
    ))
    def test_create_zone_fuzz_param(self, parameter, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        test_model = datagen.random_zone_data()

        if parameter == 'masters':
            test_model.__dict__[parameter] = [payload]
        else:
            test_model.__dict__[parameter] = payload

        result = fuzzer.verify_tempest_exception(
            self.client.post_zone, fuzz_type, test_model)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    header_params = ['accept', 'content-type']

    @utils.parameterized(fuzzer.get_param_datasets(
        header_params, ['content_types', 'junk', 'sqli', 'xss', 'rce', 'huge']
    ))
    def test_fuzzed_zone_header(self, parameter, fuzz_type, payload):
        model = datagen.random_zone_data()
        headers = {
            'content-type': 'application/json',
            'accept': ''
        }
        headers[parameter] = payload.encode('utf-8')
        result = fuzzer.verify_tempest_exception(
            self.client.post_zone, fuzz_type, model, headers=headers)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_param_datasets(
        zone_params, ['junk', 'sqli', 'xss', 'rce', 'huge']
    ))
    def test_update_zone_fuzz_param(self, parameter, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        resp, old_model = self._create_zone(datagen.random_zone_data())
        patch_model = old_model
        if parameter == 'masters':
            old_model.__dict__[parameter] = [payload]
        else:
            old_model.__dict__[parameter] = payload

        result = fuzzer.verify_tempest_exception(
            self.client.patch_zone, fuzz_type, old_model.id, patch_model)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['content_types', 'number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_zone_fuzz_header(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        test_resp, test_model = self._create_zone(
                                        datagen.random_zone_data())
        headers = {"Accept": payload}
        result = fuzzer.verify_tempest_exception(
            self.client.get_zone, fuzz_type, test_model.id, headers=headers)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_zone_nameservers_fuzz_uuid(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.client.get, fuzz_type,
            url='/v2/zones/{0}/nameservers'.format(payload))
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_zone_transfer_fuzz_uuid(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.client.get, fuzz_type,
            url='/zones/tasks/transfer_requests/{0}'.format(payload))
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_abandon_zone_fuzz_uuid(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.client.post, fuzz_type,
            url='/v2/zones/{0}/tasks/abandon'.format(payload), body='')
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_transfer_fuzz_uuid(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.client.post, fuzz_type,
            url='/v2/zones/{0}/tasks/transfer_requests'.format(payload),
            body='')
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    filters = [
        'limit', 'marker', 'sort_dir', 'type', 'name', 'ttl', 'data',
        'description', 'status'
    ]

    @utils.parameterized(fuzzer.get_param_datasets(
        filters, ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_list_zones_fuzzed_filter(self, parameter,
                                      fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.list_zones, fuzz_type, filters={parameter: payload})
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    def _create_zone(self, zone_model, user='default'):
        resp, model = ZoneClient.as_user(user).post_zone(zone_model)
        self.assertEqual(resp.status, 202)
        # ZoneClient.as_user(user).wait_for_zone(model.id)
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
    # @utils.parameterized(fuzzer.get_datasets(
    #     ['content_types', 'junk', 'sqli', 'xss', 'rce']
    # ))
    # def test_create_zone_import_fuzz_content_type_header(
    #         self, fuzz_type, payload):
    #     zonefile = datagen.random_zonefile_data()
    #     headers = {"Content-Type": payload.encode('utf-8')}
    #     result, exception = fuzzer.verify_tempest_exception(
    #         self.client.post_zone_import,
    #         fuzz_type, zonefile, headers=headers)
    #     self.assertTrue(result)
    #     if exception:
    #         self.assertIsInstance(exception, exceptions.InvalidContentType)

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_import_fuzz_name(
            self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
                payload = urllib.quote_plus(payload.encode('utf-8'))
        zonefile = datagen.random_zonefile_data(name=payload)
        result = fuzzer.verify_tempest_exception(
            self.client.post_zone_import,
            fuzz_type, zonefile)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_zone_import_fuzz_ttl(
            self, fuzz_type, payload):
        if type(payload) is str or type(payload) is unicode:
            payload = urllib.quote_plus(payload.encode('utf-8'))
        zonefile = datagen.random_zonefile_data(ttl=payload)
        result = fuzzer.verify_tempest_exception(
            self.client.post_zone_import,
            fuzz_type, zonefile)
        self.assertTrue(result)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))
