
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
    state:
        description:
            - present Will make shure the upstream is present in config
            - absent Will make shure the upstream is absent in config
        required: false
        default: "present"

author:
    - Alexandr Bushuev (jjjbushjjj@gmail.com)
'''
EXAMPLES = '''
# Add new upstream
- name: Ensure upstream is present
  ptaf_upstream:
    name: ololo.mydomain.com
    api_user: api_user
    api_pass: api_pass

# Remove upstream
- name: Ensure upstream is absent
  ptaf_upstream:
    name: ololo.mydomain.com
    api_user: api_user
    api_pass: api_pass
    state: absent
'''

def upstream_exists(name):
    """ Return true if upstream already exists, othewise false. Based on name param """
    pass

def upstream_info(name):
    """ Dump all upstream info from device, returns dict with all params."""
    pass

def upstream_matches(params):
    """ Compare all upstream params with correspondig values from uptream_info().
        Returns global changed state and list of unmached params"""
    pass

def upstream_add(params):
    """ Add new upstream if it is not present. Also modify all unmached params"""
    if not upstream_exists():
        # Add new upstream and set all params
        pass
    else:
        # Get all unmached params
        unmached_params = upstream_matches(params)[1:]
        # Set all unmached params
    pass

def upstream_del(name):
    """ Delete upstream if it is present."""
    if upstream_exists():
        # delete it
        pass
    pass


from ansible.module_utils.basic import AnsibleModule

def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        name=dict(type='str', required=True),
        api_url=dict(type='str', required=False, default="https://localhost:8080/wcs/api/v1"),
        api_user=dict(type='str', required=True),
        api_pass=dict(type='str', required=True),
        state=dict(type='str', required=False, default="present")
    )
    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    p = module.params

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        if p['state'] == "absent":
            changed = upstream_exists(p['name'])
        elif p['state'] == "present":
            changed = not upstream_matches(p)[0]
        module.exit_json(changed=changed, upstream=p['name'])

    if p['state'] == "absent":
        changed = upstream_del(p['name'])
    else:
        changed = upstream_add(p)

    module.exit_json(changed=changed, upstream=p['name'])


def main():
    run_module()

if __name__ == '__main__':
    main()