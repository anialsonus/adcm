import os


TYPES = (
    "string",
    "password",
    "integer",
    "text",
    'boolean',
    'float',
    'option',
    'list',
    'map',
    'json',
    'file',
)
template = """
- type: cluster
  name: {0}_required_{1}
  version: 1
  config:
    - name: {0}_required_{1}
      type: {0}
      required: {1}
"""
template_option = """
- type: cluster
  name: {0}_required_{1}
  version: 1
  config:
    - name: {0}_required_{1}
      type: {0}
      option: {{http: 80, https: 443}}
      required: {1}
"""

TEMPLATES = {
    "string": template,
    "password": template,
    "integer": template,
    "text": template,
    'boolean': template,
    'float': template,
    'option': template_option,
    'list': template,
    'map': template,
    'json': template,
    'file': template,
}

for t in TYPES:
    for config in ('true', 'false'):
        d_name = f"{config}/{t}"
        os.makedirs(d_name)
        tmpl = ''
        with open(f"{d_name}/config.yaml", "w+", encoding='utf_8') as f:
            f.write(TEMPLATES[t].format(t, config))
