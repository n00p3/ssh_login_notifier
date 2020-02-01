import select
import time
from   systemd import journal
# You need version > 5.1, update using pip3 install -U pyyaml.
import yaml
import logging
import re
import datetime
import smtplib
import platform


class Event:
    """
    Event class.
    If `type` is falsy, then `ip` and `user` should be `None`.

    Args:
        e_type    (str?): Type of event. Accepted types: 
                          None, 'auth_fail', 'auth_success'.
        ip        (str?): IP of client.
        user      (str?): Used login.
        timestamp (str):  Timestamp of event.
    """
    def __init__(self, e_type, ip, user, timestamp):
        if e_type not in [None, 'auth_fail', 'auth_success']:
            raise TypeError(f'Invalid event type ({e_type})')

        self.type      = e_type
        self.ip        = ip
        self.user      = user
        self.timestamp = timestamp
        if not bool(self.type):
            self.ip   = None
            self.user = None


    def __eq__(self, other):
        return self.type      == other.type and \
               self.ip        == other.ip   and \
               self.user      == other.user and \
               self.timestamp == other.timestamp

    def __ne__(self, other):
        return self.type      != other.type or \
               self.ip        != other.ip   or \
               self.user      != other.user or \
               self.timestamp != other.timestamp

    def __str__(self):
        return (f'\ttype:      {self.type}\n'
                f'\t\tip:        {self.ip}\n'
                f'\t\tuser:      {self.user}\n'
                f'\t\ttimestamp: {self.timestamp}')
                   

def read_config(path='./config.yml') -> dict:
    """
    Reads yaml config file, by default in the same directory as this .py file.

    Args:
        path (str): Path to config file.
    """
    with open(path) as file:
        config = yaml.load(file, Loader=yaml.FullLoader)

    return config


def prepare_logging(config):
    """
    Setups logging.

    Args:
        config (dict): Config dictionary.
    """

    log_file = config['configuration']['log_file']
    if not bool(log_file):
        log_file = './notifier.log'

    logging.basicConfig(filename=log_file,
                        filemode='a',
                        level=logging.INFO,
                        format='%(name)s - %(levelname)s - %(message)s')


def event_parser(timestamp, message) -> list:
    """
    Reads event and returns its types.

    Args:
        timestamp (datetime): Timestamp of event.
        message   (str):      Log message to parse.

    Returns: `Event` object
    """
    event = Event(None, None, None, datetime.datetime.now())
    re_fail    = re.compile(r'.*Failed password for \w+ from .*$')
    re_success = re.compile(r'.*Accepted password for \w+ from .*$')
    for line in message.split('\n'):
        if re_fail.fullmatch(line):
            user     = line.split()[5]
            ip       = line.split()[3]
            event =  Event('auth_fail',    user, ip, timestamp)
        elif re_success.fullmatch(line):
            user     = line.split()[5]
            ip       = line.split()[3]
            event =  Event('auth_success', user, ip, timestamp)
    
    return event


def filter_event(event, config) -> list:
    """
    Discards disabled events, None type and whitelisted IP events.

    Args:
        event  (Event): Event.
        config (dict): Config file.

    Returns:
        List of enabled events.
    """

    auth_fail    = config['notifications']['auth_fail']   ['enable']
    auth_success = config['notifications']['auth_success']['enable']
    whitelist    = config['whitelist']

    if event.ip in whitelist:
        return None

    if auth_fail and event.type == 'auth_fail':
        return event

    if auth_success and event.type == 'auth_success':
        return event

    return None


def replace_special_vars(event, email):
    """
    Replaces $IP, $USER and $MACHINE

    Args:
        event (Event): Event with data to replace email content.
        email (str):   Message or subject content.
    """
    email = email.replace('$IP',      event.ip)
    email = email.replace('$USER',    event.user)
    email = email.replace('$MACHINE', platform.node())

    return email

def send_message(event, config):
    """
    Send an email message.

    Args:
        event  (Event): Event.
        config (dict):  Config dictionary.

    Returns:
        Boolean.
    """
    try:
        server  = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()

        me      = config['emails']['source_email']['address']
        passwd  = config['emails']['source_email']['password']
        targets = config['emails']['target_emails']

        subject = config['notifications'][event.type]['subject']
        message = config['notifications'][event.type]['message']

        subject = replace_special_vars(event, subject)
        message = replace_special_vars(event, message)

        server.login(me, passwd)
        server.sendmail(me, targets, f'Subject: {subject}\n\n{message}')
        server.close()

        logging.info('Email sent!')
    except Exception as e:
        logging.info(f'Error sending email... {e}')


if __name__ == '__main__':
    startTimestamp = datetime.datetime.now()

    config = read_config()
    prepare_logging(config)
    logging.info('SSH login notifier started.')

    j = journal.Reader()
    j.this_boot()
    j.add_match(_SYSTEMD_UNIT="ssh.service")
    j.seek_realtime(startTimestamp)

    logging.info('Waiting for events...')
    p = select.poll()
    p.register(j, j.get_events())
    p.poll()

    try:
        while True:
            event = j.get_next()
            time.sleep(float(config['configuration']['polling_freq']))
            if 'SYSLOG_TIMESTAMP' not in event or 'MESSAGE' not in event:
                continue
            ev_obj = event_parser(event['SYSLOG_TIMESTAMP'], event['MESSAGE'])
            ev_obj = filter_event(ev_obj, config)
            if ev_obj:
                logging.info('================================================')
                logging.info('new Event:')
                logging.info(ev_obj)
                send_message(ev_obj, config)
                logging.info('================================================')
    except Exception as e:
        p.unregister(j)
        logging.info(e)