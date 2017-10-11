# datadog-custom-checks

Collection of my own datadog checks

### domain_expiry

pywhois required

/opt/datadog-agent/embedded/bin/pip install python-whois

### up_down

Provides site.up and site.down metrics per tag. This allows for the creation of a SLA calculation within screen boards using the following calculation:

```
100 * ( sum:site.up{client:*} by {client}.rollup(sum) / ( sum:site.up{client:*} by {client}.rollup(sum) + sum:site.down{client:*} by {client}.rollup(sum) ) )"
```
