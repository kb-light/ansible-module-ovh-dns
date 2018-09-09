#!/usr/bin/python

# Copyright: 2018, Karsten Boeddeker (@kb-light)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community',
}

DOCUMENTATION = '''
module: ovh_dns
author: Karsten Boeddeker (@kb-light)
short_description: Manage DNS entries via ansible and the OVH API
description:
    - Manages DNS entries via the OVH API U(https://api.ovh.com/) and the corresponding python wrapper
      U(https://github.com/ovh/python-ovh).
    - You can reques your API keys via U(https://eu.api.ovh.com/createApp/) or
      U(https://api.ovh.com/createToken/index.cgi).
notes:
    - The environmental variables 'OVH_ENDPOINT', 'OVH_APPLICATIONKEY', 'OVH_APPLICATION_SECRET'
      and 'OVH_CONSUMER_KEY' should be present. It is also possible to serve this values via a
      config file. See U(https://github.com/ovh/python-ovh) for more information.
requirements: ['ovh']
options:
    zonename:
        required: true
        description:
            - The internal name of your zone.
    fieldtype:
        default: A
        choices: ['A', 'AAAA', 'CAA', 'CNAME', 'DKIM', 'DMARC', 'LOC', 'MX',
                  'NAPTR', 'NS', 'PTR', 'SPF', 'SRV', 'SSHFP', 'TLSA', 'TXT']
        description:
            - Resource record Name (A, AAAA, CNAME, ...).
    subdomain:
        default: ''
        description:
            - Resource record subdomain, can be relative to zone or absolute (ends with '.').
    target:
        description:
            - Resource record target(s), can be a list.
    ttl:
        description:
            - Resource record ttl.
    state:
        default: present
        choices: ['present', 'absent', 'get']
        description:
            - Specifies the state of the resource record.
'''

EXAMPLES = '''
# add www.example.com as an A record
- ovh_dns:
    zonename: example.com
    subdomain: www
    target: 192.0.2.1

# add two additional IPs to www.example.com, with absolute subdomain
- ovh_dns:
    zonename: example.com
    subdomain: www.example.com.
    target:
        - 192.0.2.2
        - 192.0.2.3

# update ttl of www.example.com and set API key via environment variables
- ovh_dns:
    zonename: example.com
    subdomain: www
    target:
        - 192.0.2.1
        - 192.0.2.2
        - 192.0.2.3
    ttl: 3600
  environment:
    OVH_ENDPOINT: "{{ ovh_endpoint }}"
    OVH_APPLICATION_KEY: "{{ ovh_application_key }}"
    OVH_APPLICATION_SECRET: "{{ ovh_application_secret }}"
    OVH_CONSUMER_KEY: "{{ ovh_consumer_key }}"

# remove TXT record 'hello world' from mail01.example.com
- ovh_dns:
    state: absent
    zonename: example.com
    fieldtype: TXT
    subdomain: mail01
    target: hello world

# get all AAAA records for www.example.com
- ovh_dns:
    state: get
    zonename: example.com
    fieldtype: AAAA
    subdomain: www
'''

RETURN = '''
records:
  description: returns specified resource records
  returned: when state is 'get'
  type: complex
  contains:
    fieldType:
      description: record type
      returned: always
      type: string
      sample: A
    id:
      description: record ID
      returned: always
      type: int
      sample: 12345678
    subDomain:
      description: record subdomain
      returned: always
      type: string
      sample: www.example.com.
    target:
      description: record value
      returned: always
      type: string
      sample: 192.0.2.1
    ttl:
      description: record ttl
      returned: always
      type: int
      sample: 0
    zone:
      description: zone name
      returned: always
      type: string
      sample: example.com
'''

try:
    import ovh
    # from ovh.exceptions import APIError
    HAS_OVH = True
except ImportError:
    HAS_OVH = False

from ansible.module_utils.basic import AnsibleModule


# match records depending on paramName and paramVal
def match_records(records, paramName, paramVal):
    match = []
    nomatch = []
    missing = list(paramVal)

    for record in records:
        if record[paramName] in paramVal:
            match.append(record)
            missing.remove(record[paramName])
        else:
            nomatch.append(record)

    return match, nomatch, missing


# get zone records
# searchParam should be a dict containing zoneName (required), fieldType (optional) and subDomain (optional).
def get_records(conn, searchParam):
    recordIds = []
    if 'fieldType' in searchParam and 'subDomain' in searchParam:
        recordIds = conn.get(
            '/domain/zone/{0}/record'.format(searchParam['zoneName']),
            fieldType=searchParam['fieldType'],
            subDomain=searchParam['subDomain'],
        )

    elif 'fieldType' in searchParam:
        recordIds = conn.get(
            '/domain/zone/{0}/record'.format(searchParam['zoneName']),
            fieldType=searchParam['fieldType'],
        )

    elif 'subDomain' in searchParam:
        recordIds = conn.get(
            '/domain/zone/{0}/record'.format(searchParam['zoneName']),
            subDomain=searchParam['subDomain'],
        )

    else:
        recordIds = conn.get(
            '/domain/zone/{0}/record'.format(searchParam['zoneName']),
        )

    records = []
    for recordId in recordIds:
        records.append(conn.get(
            '/domain/zone/{0}/record/{1}'.format(searchParam['zoneName'], recordId)
        ))

    return records


# delete records
def delete_records(module, conn, records):
    if records == []:
        return False

    if module.check_mode:
        return True

    for record in records:
        conn.delete(
            '/domain/zone/{0}/record/{1}'.format(record['zone'], record['id'])
        )

    return True


# generate records based on target values
def gen_records(module, target):
    records = []
    record = dict(
        zone=module.params.get('zonename'),
        fieldType=module.params.get('filetype'),
        subDomain=module.params.get('subdomain')
    )

    if module.params.get('ttl'):
        record['ttl'] = module.params.get('ttl')

    for value in target:
        record['target'] = value
        records.append(record)

    return records


# add records
def add_records(module, conn, records):
    if records == []:
        return False

    if module.check_mode:
        return True

    for record in records:
        if 'ttl' in record:
            conn.post(
                '/domain/zone/{0}/record'.format(record['zone']),
                fieldType=record['fieldType'],
                subDomain=record['subDomain'],
                target=record['target'],
                ttl=record['ttl'],
            )
        else:
            conn.post(
                '/domain/zone/{0}/record'.format(record['zone']),
                fieldType=record['fieldType'],
                subDomain=record['subDomain'],
                target=record['target'],
            )

    return True


# update records
def update_records(module, conn, records):
    if records == []:
        return False

    if module.check_mode:
        return True

    for record in records:
        conn.put(
            '/domain/zone/{0}/record/{1}'.format(record['zone'], record['id']),
            subDomain=record['subDomain'],
            target=record['target'],
            ttl=record['ttl'],
        )

    return True


# function to update ttl value
def update_records_ttl(module, conn, records):
    ttl = module.params.get('ttl')
    updateRecords = []

    for record in records:
        if record['ttl'] == ttl:
            continue

        record['ttl'] = ttl
        updateRecords.append(record)

    return update_records(module, conn, updateRecords)


# refresh the domain zone
def refresh_zone(module, conn):
    conn.post('/domain/zone/{0}/refresh'.format(module.params.get('zonename')))


def main():
    argumentSpec = dict(
        zonename=dict(required=True),
        subdomain=dict(default=''),
        target=dict(required=False, type='list'),
        fieldtype=dict(default='A', choices=['A', 'AAAA', 'CAA', 'CNAME', 'DKIM', 'DMARC', 'LOC', 'MX', 'NAPTR',
                                             'NS', 'PTR', 'SPF', 'SRV', 'SSHFP', 'TLSA', 'TXT']),
        ttl=dict(type='int'),
        state=dict(default='present', choices=['present', 'absent', 'get']),
    )

    module = AnsibleModule(
        argument_spec=argumentSpec,
        supports_check_mode=True,
    )

    state = module.params.get('state')

    # fail if ovh is missing
    if not HAS_OVH:
        module.fail_json(msg='ovh python module is required to run this module.')

    # setup connection
    conn = ovh.Client()

    # get subDomain records
    searchParam = dict(
        zoneName=module.params.get('zonename'),
        fieldType=module.params.get('fieldtype'),
        subDomain=module.params.get('subdomain'),
    )
    records = get_records(conn, searchParam)

    # match records by target
    match, noMatch, missing = match_records(records, 'target', module.params.get('target'))

    changed = False
    if state == 'absent':
        changed = delete_records(module, conn, match) or changed

    elif state == 'present':
        newRecords = gen_records(module, missing)
        changed = add_records(module, conn, newRecords) or changed
        if module.params.get('ttl'):
            changed = update_records_ttl(module, conn, match) or changed

    elif state == 'get':
        module.exit_json(records=match, changed=changed)

    # refresh zone if records have changed
    if changed:
        refresh_zone(module, conn)

    # done, exit
    module.exit_json(changed=changed, records=records)


if __name__ == '__main__':
    main()
