import re
import time
from datetime import datetime

def parse_web(logger, line):
    m = re.search(r"([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}),[0-9]* (\[[\w\-]*\]) ([A-Z]*) (.*)", line)
    if m is not None:
    
        date = m.group(1)
        thread = m.group(2)
        level = m.group(3)
        message = m.group(4)

        date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
        date = time.mktime(date.timetuple())

        metric_name = "Unify Log"

        metric_value = level.strip()

        attr_dict = {'thread': thread.strip(), 'message': message.strip()}

        return (metric_name, date, metric_value, attr_dict)

    else:
        return None

def test():
    test_input = "2016-09-23 09:04:48,792 [pool-88408-thread-1] ERROR vyre.realms.jdbc.JDBCRealm - Could not get DB connection"
    
    logger = "TODO"

    parse_web(logger, test_input)

if __name__ == '__main__':
    # For local testing, callable as "python /path/to/parsers.py"
    test()
