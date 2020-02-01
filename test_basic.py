import unittest
import ssh_login_notifier as proj
import datetime


class BasicTest(unittest.TestCase):
    def test_event_class(self):
        e = proj.Event('auth_fail', None, None, None)
        self.assertEqual(e.type, 'auth_fail')
        self.assertEqual(e.ip, None)
        self.assertEqual(e.user, None)

        e = proj.Event(None, '123', '456', 'lut 01 19:11:21')
        self.assertEqual(e.type, None)
        self.assertEqual(e.ip, None)
        self.assertEqual(e.user, None)

        self.assertRaises(TypeError, proj.Event, 'abc', None, None)

        self.assertEqual(proj.Event('auth_fail', 'a', 'b', 'lut 01 16:19:38'), 
                         proj.Event('auth_fail', 'a', 'b', 'lut 01 16:19:38'))

        self.assertNotEqual(
            proj.Event('auth_fail', 'a',  'b', 'lut 01 16:19:38'), 
            proj.Event('auth_fail', 'ax', 'b', 'lut 01 16:19:38'))

        self.assertNotEqual(
            proj.Event('auth_fail', 'a', 'b', 'lut 01 16:19:38'), 
            proj.Event('auth_fail', 'a', 'b', 'lut 01 20:20:39'))


    def test_event_parser(self):
        now = datetime.datetime.now()
        config = proj.read_config()

        input = '''Failed password for n00p3 from 127.0.0.1 port 59872 ssh2'''
        ev  = proj.event_parser(now, input)
        ev2 = proj.Event('auth_fail', '127.0.0.1', 'n00p3', now)
        self.assertEqual(ev, ev2)

        inputs = [
            'Connection closed by authenticating user reimu 127.0.0.1 port 59814 [preauth]',
            'Connection closed by authenticating user reimu 127.0.0.1 port 59864 [preauth]',
            'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=reimu',
            'Failed password for reimu from 127.0.0.1 port 59872 ssh2',
            'Failed password for reimu from 127.0.0.1 port 59872 ssh2',
            'Connection closed by authenticating user reimu 127.0.0.1 port 59872 [preauth]',
            'PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=reimu',
            'Accepted password for reimu from 127.0.0.1 port 59880 ssh2',
            'pam_unix(sshd:session): session opened for user reimu by (uid=0)',
            'Accepted password for reimu from 127.0.0.1 port 60010 ssh2',
            'pam_unix(sshd:session): session opened for user reimu by (uid=0)',
            'Accepted password for reimu from 127.0.0.1 port 33556 ssh2',
            'pam_unix(sshd:session): session opened for user reimu by (uid=0)'
        ]
        # TODO.

    def test_filter_events(self):
        now = datetime.datetime.now()

        evs = [
            proj.Event('auth_fail',    '127.0.0.1', 'reimu', now),
            proj.Event('auth_fail',    '127.0.0.1', 'reimu', now),
            proj.Event('auth_fail',    '127.0.0.1', 'reimu', now),
            proj.Event('auth_success', '127.0.0.1', 'reimu', now),
            proj.Event('auth_success', '127.0.0.1', 'reimu', now),
            proj.Event('auth_success', '127.0.0.1', 'reimu', now),
            proj.Event(None,           '127.0.0.1', 'reimu', now),
            proj.Event(None,           None,    None,        None)
        ]

        # config = proj.read_config()
        # config['notifications']['auth_fail']   ['enable'] = False
        # config['notifications']['auth_success']['enable'] = True

        # filtered = proj.filter_events(evs, config)
        # self.assertEqual(0, len([event for event 
        #                                in filtered 
        #                                if event.type == 'auth_fail']))

        # self.assertEqual(3, len([event for event 
        #                                in filtered 
        #                                if event.type == 'auth_success']))

        # config['notifications']['auth_fail']['enable'] = True

        # filtered = proj.filter_events(evs, config)
        # self.assertEqual(3, len([event for event 
        #                                in filtered 
        #                                if event.type == 'auth_fail']))

        # self.assertEqual(0, len([event for event 
        #                                in filtered 
        #                                if event.type == None]))


    def test_special_vars_replace(self):
        string = 'ip: $IP, user: $USER'
        event = proj.Event('auth_fail', 
                           '127.0.0.1',
                           'reimu',
                           datetime.datetime.now())
        
        replaced = proj.replace_special_vars(event, string)
        self.assertEqual(replaced, 'ip: 127.0.0.1, user: reimu')