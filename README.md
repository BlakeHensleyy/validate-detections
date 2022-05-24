# Analytics Rules Validator

This GitHub action can be used to validate Microsoft Sentinel Analytics rules in both JSON and YML format.
Add the following code block to your Github workflow:

```yaml
name: Analytics
on: push

jobs:
  pester-test:
    name: Validate Detections
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository code
        uses: actions/checkout@v3
      - name: Validate Sentinel Analytics Rules
        uses: SecureHats/validate-detections@v1.2.0
        with:
          filesPath: templates
```

> Use the filesPath parameter to specify the folder containing the detection rules.

## Current incuded tests

![image](https://user-images.githubusercontent.com/40334679/170026369-fa0fa7b8-e580-42d4-9c2d-c36edb506094.png)

## Current limitations / Under Development

- No support for Hunting Queries
- No support for Fusion rules
