
#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ptaf_upstream

short_description: This module manages upstreams in PTAF

version_added: "2.4"

description:
    - "This module automates Upstreams configuration on Positive Technology Application Firewall (PTAF)"

options:
    name:
        description:
            - Upstream name
        required: true
    api_url:
        description:
            - Main url for api calls
        required: false
        default: "https://{{play_host}}:8080/api/wcs/v1"
    api_user:
        description:
            - Username with api access rights
        required: true
    api_pass:
        description:
            - Password for user
        required: true
    backends:
        descriptrion:
            - List of backends
        backend:
            description:
                - Backend config params
            address:
                descriptrion:
                    - backend address
                required: true
            backup
                description:
                    - backend backup flag
                required: true
                default: false
            down
                descriptrion:
                    - backend down flag
                required: true
                default: false
            max_fails
                descriptrion:
                    - backend maximun number of fails
                required: true
                default: null
            port
                descriptrion:
                    - backend port
                required: true
                default: 80
            weight
                descriptrion:
                    - backends weight
                required: true
                default: 1
    ip_hashing:
        description:
            - Use or not ip_hash method
        required: false
        default: false
    least_conn:
        descriptrion:
            - Use or not least_conn method
        required: false
        default: false
    transparency:
        description:
            - Enable transparent mode for upstream
        required: false
        default: false
    keep_alive:
        description:
            - Number of idle connections per worker
        required: false
        default: 32
    read_timeout:
        description:
            - Read timeout from proxied server
        default: 60
    state:
        description:
            - present Will make shure the upstream is present in config
            - absent Will make shure the upstream is absent in config
        required: false
        choices: ['present', 'absent']
        default: 'present'
    validate_certs:
        description:
            - If C(no), SSL certificates will not be validated. This should only be used
              on personally controlled sites using self-signed certificates.
        required: false
        default: 'yes'
        choices: ['yes', 'no']

author:
    - Alexandr Bushuev (jjjbushjjj@gmail.com)
requirenents:
    - PTAF API Access
'''
EXAMPLES = '''
# Add new upstream
- name: Ensure upstream is present
  ptaf_upstream:
  name: test
  api_user: "user"
  api_pass: "pass"
  api_url: "https://ptaf-02.mydomain.com:8080/api/waf/v2"
  validate_certs: no
  backends:
    -
      address: "2.1.1.1"
      port: 80
      weight: 1
      max_fails: null
      down: false
      backup: false
    -
      address: "2.2.2.2"
      port: 8080
      weight: 2
      max_fails: null
      down: true
      backup: false
  ip_hash: false
  least_conn: false
  transparent: false
  keepalive: 32
  state: present

# Remove upstream
- name: Ensure upstream is absent
  ptaf_upstream:
  name: test
  api_user: "user"
  api_pass: "pass"
  api_url: "https://ptaf-01.mydomain.com:8080/api/waf/v2"
  validate_certs: no
  backends:
    -
      address: "2.1.1.1"
      port: 80
      weight: 1
      max_fails: null
      down: false
      backup: false
  state: absent
'''

def compose_payload(params):
    """ Get config params and cut all unused for api call return correct payload """
    data=dict(params)
    # remove all unused params from payload so basically this makes all dicts keys in sync
    absent_keys=['api_user', 'api_pass', 'api_url', 'validate_certs', 'state', 'addresses', 'id', 'last_modified']
    for key in absent_keys:
        if data.has_key(key):
            data.pop(key, None)
    # Sort and serialize into json
    data = json.dumps(data, sort_keys=True)
    return data

def upstream_exists(module, params):
    """ Return true and upstream config if upstream already exists, othewise false. Based on name param """
    for upstream in upstreams_info(module, params)['items']:
        if upstream['name'] == params['name']:
            url = params['api_url'] + "/upstreams/" + upstream['id']
            headers=set_headers(params['api_user'], params['api_pass'])
            resp, info = fetch_url(module, url, method='GET', headers=headers)
            if info['status'] != 200:
                module.fail_json(msg=" failed to send upstream get request responce is %s" % info)
            return True, json.loads(resp.read())

    return False, {}
    

def upstreams_info(module, params):
    """ Dump all upstream info from device, returns dict with all params."""
    url = params['api_url'] + "/upstreams"
    headers=set_headers(params['api_user'], params['api_pass'])
    # Fetch all upstreams 
    resp, info = fetch_url(module, url, method='GET', headers=headers)
    if info['status'] != 200:
        module.fail_json(msg=" Info failed to send upstream get request responce is %s" % info)
    return json.loads(resp.read())

def upstream_matches(module, params):
    """ Compare all upstream params with correspondig values from upstream_exists()"""
        
    exists, device_upstream = upstream_exists(module, params)
    device_upstream = compose_payload(device_upstream)
    # Now we have all upstream params from device we need to match them with module params
    config_upstream = compose_payload(params)
    if config_upstream == device_upstream:
        return True 

    return False

def upstream_add(module, params):
    """ Add new upstream if it is not present. Also modify all unmached params"""
    exists, upstream = upstream_exists(module, params)
    if not exists:
        # Add new upstream and set all params
        url = params['api_url'] + "/upstreams"
        headers = set_headers(params['api_user'], params['api_pass'])
        data = compose_payload(params)
        # POST new upstream config
        resp, info = fetch_url(module, url, data=data, method='POST', headers=headers)
        if info['status'] != 201:
            module.fail_json(msg="Failed to add new upstream %s " % info)
        return True
    elif not upstream_matches(module, params): 
        # Configs don't match so PATCH all remote config
        i_d = upstream['id']
        url = params['api_url'] + "/upstreams/" + i_d
        headers = set_headers(params['api_user'], params['api_pass'])
        data = compose_payload(params)
        resp, info = fetch_url(module, url, data=data, method='PATCH', headers=headers)
        if info['status'] != 200:
            module.fail_json(msg="Failed to update upstream %s " % info)
        return True

    return False

def upstream_del(module, params):
    """ Delete upstream if it is present."""
    exists, upstream = upstream_exists(module, params)
    if exists:
        i_d = upstream['id']
        url = params['api_url'] + "/upstreams/" + i_d
        headers = set_headers(params['api_user'], params['api_pass'])
        resp, info = fetch_url(module, url, method='DELETE', headers=headers)
        if info['status'] != 200:
            module.fail_json(msg="Failed to delete upstream %s " % info)
        return True

    return False

def set_headers(user, passwd):

    auth = 'Basic ' + base64.encodestring('%s:%s' % (user, passwd)).replace('\n', '')
    headers = {
       'Authorization': auth,
       'Content-Type' : 'application/json',
    }
    return headers


import base64
import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url

def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        name=dict(type='str', required=True),
        api_url=dict(type='str', required=False, default="https://localhost:8080/api/waf/v2"),
        api_user=dict(type='str', required=True),
        api_pass=dict(type='str', required=True, no_log=True),
        state=dict(type='str', required=False, default="present", choices=['present', 'absent']),
        validate_certs=dict(default='yes', type='bool'),
        backends=dict(type='list', required=True,
                address=dict(type='str', required=True),
                port=dict(type='int', required=True, default=80),
                weight=dict(type='int', required=True, default=1),
                max_fails=dict(type='str', required=True, default='null'),
                down=dict(type='bool', required=True, default=False),
                backup=dict(type='bool', required=True, default=False)
        ),
        ip_hash=dict(type='bool', default=False, required=False),
        least_conn=dict(type='bool', default=False, required=False),
        transparent=dict(type='bool', default=False, required=False),
        keepalive=dict(type='int', default=32, required=False),
        read_timeout=dict(type='int', default=60, required=False)
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )


    state = module.params['state']
    name = module.params['name']
    p = module.params

    # dirty check for misspeled/unsupported params
    valid_params = ['name', 'api_url', 'api_user', 'api_pass', 'state',
            'validate_certs', 'backends', 'ip_hash', 'least_conn', 'transparent', 'keepalive', 'read_timeout']
    valid_params_backends = ['address', 'port', 'weight', 'max_fails', 'down', 'backup']

    for key in p.keys():
        if key not in valid_params:
            module.fail_json(msg="Unknown parameter %s " % key)

    for back in p['backends']:
        for key in back.keys():
            if key not in valid_params_backends:
                module.fail_json(msg="Unknown parameter %s " % key)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        if state == "absent":
            changed, upstream = upstream_exists(module,p)
        elif state == "present":
            changed = not upstream_matches(module,p)
        module.exit_json(changed=changed)

    if state == "absent":
        changed = upstream_del(module,p)
    else:
        changed = upstream_add(module,p)

    module.exit_json(changed=changed, upstream=name)


def main():
    run_module()

if __name__ == '__main__':
    main()
