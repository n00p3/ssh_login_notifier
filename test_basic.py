import unittest
import ssh_login_notifier as proj


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
        input = '''lut 01 16:19:38 n00p3-desktop sshd[11202]: Failed password for n00p3 from 127.0.0.1 port 59872 ssh2'''
        evs = proj.event_parser(input)
        self.assertListEqual(evs, 
            [proj.Event('auth_fail', 'n00p3', '127.0.0.1', 'lut 01 16:19:38')])

        input = '''lut 01 16:15:47 reimu-desktop sshd[10920]: Connection closed by authenticating user reimu 127.0.0.1 port 59814 [preauth]
                   lut 01 16:19:04 reimu-desktop sshd[11137]: Connection closed by authenticating user reimu 127.0.0.1 port 59864 [preauth]
                   lut 01 16:19:28 reimu-desktop sshd[11202]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=reimu
                   lut 01 16:19:30 reimu-desktop sshd[11202]: Failed password for reimu from 127.0.0.1 port 59872 ssh2
                   lut 01 16:19:38 reimu-desktop sshd[11202]: Failed password for reimu from 127.0.0.1 port 59872 ssh2
                   lut 01 16:19:38 reimu-desktop sshd[11202]: Connection closed by authenticating user reimu 127.0.0.1 port 59872 [preauth]
                   lut 01 16:19:38 reimu-desktop sshd[11202]: PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=reimu
                   lut 01 16:19:46 reimu-desktop sshd[11230]: Accepted password for reimu from 127.0.0.1 port 59880 ssh2
                   lut 01 16:19:46 reimu-desktop sshd[11230]: pam_unix(sshd:session): session opened for user reimu by (uid=0)
                   lut 01 16:26:41 reimu-desktop sshd[12654]: Accepted password for reimu from 127.0.0.1 port 60010 ssh2
                   lut 01 16:26:41 reimu-desktop sshd[12654]: pam_unix(sshd:session): session opened for user reimu by (uid=0)
                   lut 01 19:11:21 reimu-desktop sshd[26188]: Accepted password for reimu from 127.0.0.1 port 33556 ssh2
                   lut 01 19:11:21 reimu-desktop sshd[26188]: pam_unix(sshd:session): session opened for user reimu by (uid=0)'''

        evs = proj.event_parser(input)
        expected = [
            proj.Event('auth_fail',    'reimu', '127.0.0.1', 'lut 01 16:19:30'),
            proj.Event('auth_fail',    'reimu', '127.0.0.1', 'lut 01 16:19:38'),
            proj.Event('auth_success', 'reimu', '127.0.0.1', 'lut 01 16:19:46'),
            proj.Event('auth_success', 'reimu', '127.0.0.1', 'lut 01 16:26:41'),
            proj.Event('auth_success', 'reimu', '127.0.0.1', 'lut 01 19:11:21')
        ]
        self.assertListEqual(evs, expected)


    def test_filter_events(self):
        evs = [
            proj.Event('auth_fail',    'reimu', '127.0.0.1', 'lut 01 19:11:21'),
            proj.Event('auth_fail',    'reimu', '127.0.0.1', 'lut 01 19:11:21'),
            proj.Event('auth_fail',    'reimu', '127.0.0.1', 'lut 01 19:11:21'),
            proj.Event('auth_success', 'reimu', '127.0.0.1', 'lut 01 19:11:21'),
            proj.Event('auth_success', 'reimu', '127.0.0.1', 'lut 01 19:11:21'),
            proj.Event('auth_success', 'reimu', '127.0.0.1', 'lut 01 19:11:21'),
            proj.Event(None,           'reimu', '127.0.0.1', 'lut 01 19:11:21'),
            proj.Event(None,           None,    None,        None)
        ]

        config = proj.read_config()
        config['notifications']['auth_fail']   ['enable'] = False
        config['notifications']['auth_success']['enable'] = True

        filtered = proj.filter_events(evs, config)
        self.assertEqual(0, len([event for event 
                                       in filtered 
                                       if event.type == 'auth_fail']))

        self.assertEqual(3, len([event for event 
                                       in filtered 
                                       if event.type == 'auth_success']))

        config['notifications']['auth_fail']['enable'] = True

        filtered = proj.filter_events(evs, config)
        self.assertEqual(3, len([event for event 
                                       in filtered 
                                       if event.type == 'auth_fail']))

        self.assertEqual(0, len([event for event 
                                       in filtered 
                                       if event.type == None]))