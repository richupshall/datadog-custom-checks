from datetime import datetime
import time
import random

from checks import AgentCheck

#Third Party
import whois

class UpDownCheck(AgentCheck):
    def check(self, instance):
        num = random.randrange(0,2)
        self.gauge('state.up', num)
        self.gauge('state.down', 1-num)
