import http.client
import json
import os
import re
from string import Template


API_KEY = os.environ["SYSDIG_API_KEY"]
POLICY_TEMPLATE = """\
resource "sysdig_secure_policy" "$name_id" {
  name        = "$name"
  description = "$description"
  enabled     = $enabled
  type        = "$type"
  severity    = $severity
  scope       = ""
  rule_names  = $ruleNames

  actions {}

  notification_channels = []
}
"""


def get_default():
    headers = {"Authorization": "Bearer {}".format(API_KEY)}
    params = {}
    conn = http.client.HTTPSConnection("secure.sysdig.com", 443)
    conn.request("GET", "/api/v2/policies/default", params, headers)
    res = conn.getresponse()
    return json.loads(res.read())

def map_format(policy):
    policy["name_id"] = re.sub('\(|\)', '', policy["name"].lower().replace(" ", "_"))
    if policy["severity"] == 3:
        policy["severity"] = 0
    elif policy["severity"] == 5:
        policy["severity"] = 4
    return policy


def map_to_template(default_policy):
    resource = Template(POLICY_TEMPLATE)
    return resource.substitute(map_format(default_policy))

result = map(map_to_template, get_default())
print("\n".join(list(map(map_to_template, get_default()))).replace("'", '"').replace("True", "true").replace("False", "false"))


