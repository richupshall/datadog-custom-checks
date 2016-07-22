from datetime import datetime
import time

from checks.network_checks import EventType, NetworkCheck, Status
from hashlib import md5

#Third Party
import whois

class DomainCheck(NetworkCheck):
    def check(self, instance):
        if 'url' not in instance:
            self.log.info("Skipping instance, no url found")
            return

        #Load values from config
        url = instance['url']
        self.log.info(url)

        #Use a hash of url as aggregation key
        aggregation_key = md5(url).hexdigest()

        record = whois.whois(url)
        today = datetime.utcnow()

        if type(record.expiration_date) is list:
            days_left = record.expiration_date[0] - today
        else:
            days_left = record.expiration_date - today

        self.log.info(days_left.days)

        if days_left.days < 0:
            status, msg = 3, "Expired by {0} days".format(days_left.days)

        elif days_left.days < 7:
            status, msg = 2, "This cert TTL is critical: only {0} days before it expires".format(days_left.days)

        elif days_left.days < 30:
            status, msg = 1, "This cert is almost expired, only {0} days left".format(days_left.days)

        else:
            status, msg =  0, "Days left: {0}".format(days_left.days)
        self.log.info(msg)
        self.log.info(status)
        self.service_check("domain.expiry2", status, tags=['environment:production','role:webserver'], message=msg)
