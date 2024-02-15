# Honeypage (pre-alpha)
Golang application to create a portable honeypot web application page with definition for use with [***modpot***](https://github.com/referefref/modpot/)

## Example output (config.yaml)
```yaml
honeypots:
- id: 1
  name: test
  cve: CVE-2021-20232
  application: nuggets
  port: 80
  template_html_file: bharatgas
  detection_endpoint: ForgotCredential
  request_regex: ^admin.*password=.*$
  date_created: "2024-02-15"
  date_updated: "2024-02-15"
```

## Folder Structure
html files (baseDir) - ./templates/
images - ./templates/assets/images/
javascript - ./templates/scripts/
