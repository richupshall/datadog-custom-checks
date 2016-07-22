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
            status, msg = Status.DOWN, "Expired by {0} days".format(days_left.days)

        elif days_left.days < 7:
            status, msg = Status.CRITICAL, "This cert TTL is critical: only {0} days before it expires".format(days_left.days)

        elif days_left.days < 30:
            status, msg = Status.WARNING, "This cert is almost expired, only {0} days left".format(days_left.days)

        else:
            status, msg =  Status.UP, "Days left: {0}".format(days_left.days)

        self.service_check("domain.expiry2", status, tags=url,message=msg)
