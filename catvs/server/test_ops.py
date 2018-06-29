# -*- coding: utf-8 -*-

import unittest, socket, logging
from struct import unpack
from ..util import TestClient, Msg

_log = logging.getLogger(__name__)

class TestScalar(TestClient, unittest.TestCase):

    user = b'foo'
    host = socket.gethostname().encode('latin-1')

    def openChan(self):
        'Open TCP connection and create channel'
        self.cid = 156
        self.connectTCP()
        self.sendTCP([
            Msg(cmd=0, dcnt=13),
            Msg(cmd=20, body=self.user),
            Msg(cmd=21, body=self.host),
            Msg(cmd=18, p1=self.cid, p2=13, body=b'ival'),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12
        self.sver = rep.dcnt

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=22, p1=self.cid, p2=3)

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=18, dtype=5, dcnt=1, p1=self.cid)
        self.sid = rep.p2

        self.live = True
        self.addCleanup(self._closeChan)

    def _closeChan(self):
        if not self.live:
            return
        self.sendTCP([
            Msg(cmd=12, p1=self.sid, p2=self.cid),
        ])

        junk=[]
        while True:
            rep = self.recvTCP()
            if rep.cmd==12:
                break
            junk.append(rep)
        self.assertCAEqual(rep, cmd=12, p1=self.sid, p2=self.cid)
        self.sid = None
        self.assertListEqual(junk, [])

    def test_get(self):
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=5, dcnt=1, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=5, dcnt=1, p1=1, p2=ioid)

        self.assertEqual(unpack('!i',rep.body[:4]), (0x2a,))

    def test_get_convert(self):
        'Get LONG as DOUBLE'
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=2, dcnt=1, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=2, dcnt=1, p1=1, p2=ioid)

        self.assertEqual(unpack('!f',rep.body[:4]), (float(0x2a),))

    def test_get_bad(self):
        'Get out of range DBR'
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=0xefef, dcnt=1, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        self.assertIsNone(rep)
        self.live = False

    def test_put(self):
        'Put w/o reply'
        self.openChan()
        ioid = 1102
        self.sendTCP([
            Msg(cmd=4, dtype=5, dcnt=1, p1=self.sid, p2=1101, body=b'\0\0\0\x2b'),
            Msg(cmd=15, dtype=5, dcnt=1, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=5, dcnt=1, p1=1, p2=ioid)

        self.assertEqual(unpack('!i',rep.body[:4]), (0x2b,))

    def test_put_bad(self):
        'Put w/o reply w/ bad DBR'
        self.openChan()
        ioid = 1102
        self.sendTCP([
            Msg(cmd=4, dtype=0xefef, dcnt=1, p1=self.sid, p2=1101, body=b'\0\0\0\x2b'),
        ])

        rep = self.recvTCP()
        if rep is None:
            # RSRV queues an error, then closes the connection before send()ing...
            self.live = False
        else:
            self.assertCAEqual(rep, cmd=11, dtype=0, dcnt=0, p1=self.cid, p2=0x72) # ECA_BADTYPE

    def test_put_callback(self):
        'Put w/ reply'
        self.openChan()
        self.sendTCP([
            Msg(cmd=19, dtype=5, dcnt=1, p1=self.sid, p2=1101, body=b'\0\0\0\x2c'),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=19, dtype=5, dcnt=1, p1=1, p2=1101)

        self.sendTCP([
            Msg(cmd=15, dtype=5, dcnt=1, p1=self.sid, p2=1102),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=5, dcnt=1, p1=1, p2=1102)

        self.assertEqual(rep.body[:4], b'\0\0\0\x2c')

    def test_put_callback_bad(self):
        'Put w/ reply w/ bad DBR'
        self.openChan()
        self.sendTCP([
            Msg(cmd=19, dtype=0xefef, dcnt=1, p1=self.sid, p2=1101, body=b'\0\0\0\x2c'),
        ])

        rep = self.recvTCP()
        if rep is None:
            # RSRV queues an error, then closes the connection before send()ing...
            self.live = False
        else:
            self.assertCAEqual(rep, cmd=19, dtype=0xefef, dcnt=1, p1=0x72, p2=1101, body=b'') # ECA_BADTYPE

    def test_monitor(self):
        self.openChan()
        ioid = 1102
        # subscribe
        self.sendTCP([
            Msg(cmd=1, dtype=5, dcnt=1, p1=self.sid, p2=ioid,
                body=Msg._sub_body.pack(0.0, 0.0, 0.0, 1)), # DBE_VALUE
        ])

        # wait for initial update
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)
        self.assertEqual(rep.body[:4], b'\0\0\0\x2a')

        # Send a Put to trigger a subscription update
        self.sendTCP([
            Msg(cmd=4, dtype=5, dcnt=1, p1=self.sid, p2=1101, body=b'\0\0\0\x2d'),
        ])

        # wait for update
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)
        self.assertEqual(rep.body[:4], b'\0\0\0\x2d')

        # cancel subscription
        self.sendTCP([
            Msg(cmd=2, dtype=5, dcnt=1, p1=self.sid, p2=ioid),
        ])

        # wait for confirmation
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)

        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=self.sid, p2=ioid, size=0)


class TestArray(TestClient, unittest.TestCase):

    user = b'foo'
    host = socket.gethostname().encode('latin-1')

    def openChan(self, cver=13):
        'Open TCP connection and create channel'
        self.cid = 156
        self.connectTCP()
        self.sendTCP([
            Msg(cmd=0, dcnt=cver),
            Msg(cmd=20, body=self.user),
            Msg(cmd=21, body=self.host),
            Msg(cmd=18, p1=self.cid, p2=cver, body=b'aval'),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=0)
        self.assertGreater(rep.dcnt, 6) # server version must be post Base 3.12
        self.sver = rep.dcnt

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=22, p1=self.cid, p2=3)

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=18, dtype=1, dcnt=5, p1=self.cid)
        self.sid = rep.p2

        self.addCleanup(self._closeChan)

    def _closeChan(self):
        self.sendTCP([
            Msg(cmd=12, p1=self.sid, p2=self.cid),
        ])

        junk=[]
        while True:
            rep = self.recvTCP()
            if rep.cmd==12:
                break
            junk.append(rep)
        self.assertCAEqual(rep, cmd=12, p1=self.sid, p2=self.cid)
        self.sid = None
        self.assertListEqual(junk, [])

    def test_get_all(self):
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=1, dcnt=5, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, size=16, cmd=15, dtype=1, dcnt=5, p1=1, p2=ioid)

        # RSRV weirdness.
        # first element is undefined when NORD==0
        # should be zero...
        if rep.body[:2]!=b'\0\0':
            _log.warn("RSRV weirdness, first element of empty array is undefined")
        self.assertEqual(rep.body[2:], b'\0'*14)

    def test_get_some(self):
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=1, dcnt=2, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, size=8, cmd=15, dtype=1, dcnt=2, p1=1, p2=ioid)

    def test_get_one(self):
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=1, dcnt=1, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, size=8, cmd=15, dtype=1, dcnt=1, p1=1, p2=ioid)

    def test_get_zero(self):
        self.openChan(cver=11) # no dynamic array support
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=1, dcnt=0, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        # reply may either ok w/ length zero or error ECA_BADCOUNT
        self.assertCAEqual(rep, cmd=15, dtype=1, p2=ioid)
        if rep.p1==1 and rep.dcnt==0: # RSRV does this
            pass
        elif rep.p1>>3==22: # PCAS does this
            pass
        else:
            self.fail("No match %s" % rep)
        # RSRV returns a body w/ 8 bytes, not sure what this is?

    def test_get_zero_dynamic(self):
        self.openChan(cver=13)
        ioid = 1102

        self.sendTCP([
            Msg(cmd=15, dtype=1, dcnt=0, p1=self.sid, p2=ioid),
        ])

        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=15, dtype=1, p2=ioid)
        if self.sver>=13:
            # Server support dynamic array size
            self.assertCAEqual(rep, p1=1)
            if rep.dcnt not in (0,5):
                self.fail("Bad count %s"%rep)
        elif rep.p1==1 and rep.dcnt==0: # RSRV does this
            pass
        elif rep.p1>>3==22: # PCAS does this
            pass
        else:
            self.fail("No match %s"%rep)
        # RSRV returns a body w/ 8 bytes, not sure what this is?

    def test_put(self):
        self.openChan()
        ioid = 1102

        self.sendTCP([
            Msg(cmd=4, dtype=1, dcnt=2, p1=self.sid, p2=1101, body=b'\0\x2b\0\x2c'),
            Msg(cmd=15, dtype=1, dcnt=5, p1=self.sid, p2=ioid),
            Msg(cmd=15, dtype=1, dcnt=2, p1=self.sid, p2=ioid+1),
        ])

        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=15, dtype=1, dcnt=5, p1=1, p2=ioid)
        self.assertEqual(rep.body, b'\0\x2b\0\x2c\0\0\0\0\0\0\0\0\0\0\0\0')
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=15, dtype=1, dcnt=2, p1=1, p2=ioid+1)
        self.assertEqual(rep.body, b'\0\x2b\0\x2c\0\0\0\0')

    def test_monitor_one_fixed(self):
        self.openChan()
        ioid = 1102
        # subscribe
        self.sendTCP([
            Msg(cmd=1, dtype=5, dcnt=1, p1=self.sid, p2=ioid,
                body=Msg._sub_body.pack(0.0, 0.0, 0.0, 1)), # DBE_VALUE
        ])

        # wait for initial update
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)

        # RSRV weirdness.
        # first element is undefined when NORD==0
        # should be zero...
        if rep.body[:2]!=b'\0\0':
            _log.warn("RSRV weirdness, first element of empty array is undefined")
        self.assertEqual(rep.body[2:4], b'\0\0')
        # should be self.assertEqual(rep.body[:4], b'\0\0\0\0')

        # Send Puts to trigger subscription updates
        self.sendTCP([
            Msg(cmd=4, dtype=5, dcnt=2, p1=self.sid, p2=1101, body=b'\0\0\0\x2a\0\0\0\x2d'),
        ])
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)
        self.assertEqual(rep.body[:4], b'\0\0\0\x2a')

        self.sendTCP([
            Msg(cmd=4, dtype=1, dcnt=4, p1=self.sid, p2=1101, body=b'\0\x2b\0\x2c\0\x2d\0\x2e'),
        ])
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)
        self.assertEqual(rep.body[:4], b'\0\0\0\x2b')

        self.sendTCP([
            Msg(cmd=4, dtype=1, dcnt=1, p1=self.sid, p2=1101, body=b'\0\x2c'),
        ])
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=1, p2=ioid)
        self.assertEqual(rep.body[:4], b'\0\0\0\x2c')

        # cancel subscription
        self.sendTCP([
            Msg(cmd=2, dtype=5, dcnt=1, p1=self.sid, p2=ioid),
        ])

        # wait for confirmation
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=1, p1=self.sid, p2=ioid, size=0)

    def test_monitor_three_fixed(self):
        self.openChan()
        ioid = 1102
        # subscribe
        self.sendTCP([
            Msg(cmd=1, dtype=5, dcnt=3, p1=self.sid, p2=ioid,
                body=Msg._sub_body.pack(0.0, 0.0, 0.0, 1)), # DBE_VALUE
        ])

        # wait for initial update
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=3, p1=1, p2=ioid)

        # RSRV weirdness.
        # first element is undefined when NORD==0
        # should be zero...
        if rep.body[:2]!=b'\0\0':
            _log.warn("RSRV weirdness, first element of empty array is undefined")
        self.assertEqual(rep.body[2:12], b'\0'*10)
        # should be self.assertEqual(rep.body[:12], b'\0'*12)

        # Send Puts to trigger subscription updates
        self.sendTCP([
            Msg(cmd=4, dtype=5, dcnt=2, p1=self.sid, p2=1101, body=b'\0\0\0\x2a\0\0\0\x2d'),
        ])
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=3, p1=1, p2=ioid)
        self.assertEqual(rep.body[:12], b'\0\0\0\x2a\0\0\0\x2d\0\0\0\0')

        self.sendTCP([
            Msg(cmd=4, dtype=1, dcnt=4, p1=self.sid, p2=1101, body=b'\0\x2b\0\x2c\0\x2d\0\x2e'),
        ])
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=3, p1=1, p2=ioid)
        self.assertEqual(rep.body[:12], b'\0\0\0\x2b\0\0\0\x2c\0\0\0\x2d')

        self.sendTCP([
            Msg(cmd=4, dtype=1, dcnt=1, p1=self.sid, p2=1101, body=b'\0\x2c'),
        ])
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=3, p1=1, p2=ioid)
        self.assertEqual(rep.body[:12], b'\0\0\0\x2c' + b'\0'*8)

        # cancel subscription
        self.sendTCP([
            Msg(cmd=2, dtype=5, dcnt=3, p1=self.sid, p2=ioid),
        ])

        # wait for confirmation
        rep = self.recvTCP()
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=3, p1=self.sid, p2=ioid, size=0)

    def test_monitor_zero_dynamic(self):
        self.openChan(cver=13)
        ioid = 1102

        # subscribe
        self.sendTCP([
            Msg(cmd=1, dtype=5, dcnt=0, p1=self.sid, p2=ioid,
                body=Msg._sub_body.pack(0.0, 0.0, 0.0, 1)), # DBE_VALUE
        ])

        # wait for initial update
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=0, p1=1, p2=ioid)

        # Send a Put to trigger a subscription update
        self.sendTCP([
            Msg(cmd=4, dtype=5, dcnt=2, p1=self.sid, p2=1101, body=b'\0\0\0\x2a\0\0\0\x2d'),
        ])
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, p2=ioid)
        if self.sver>=13:
            # Server support dynamic array size
            self.assertCAEqual(rep, p1=1, dcnt=2)
        elif rep.p1==1 and rep.dcnt==0: # RSRV does this
            pass
        elif rep.p1>>3==22: # PCAS does this
            pass
        else:
            self.fail("No match %s"%rep)
        self.assertEqual(rep.body[:8], b'\0\0\0\x2a\0\0\0\x2d')

        # Send a Put to trigger a subscription update
        self.sendTCP([
            Msg(cmd=4, dtype=1, dcnt=4, p1=self.sid, p2=1101, body=b'\0\x2b\0\x2c\0\x2d\0\x2e'),
        ])
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, p2=ioid)
        if self.sver>=13:
            # Server support dynamic array size
            self.assertCAEqual(rep, p1=1, dcnt=4)
        elif rep.p1==1 and rep.dcnt==0: # RSRV does this
            pass
        elif rep.p1>>3==22: # PCAS does this
            pass
        else:
            self.fail("No match %s"%rep)
        self.assertEqual(rep.body[:16], b'\0\0\0\x2b\0\0\0\x2c\0\0\0\x2d\0\0\0\x2e')

        # Send a Put to trigger a subscription update
        self.sendTCP([
            Msg(cmd=4, dtype=1, dcnt=1, p1=self.sid, p2=1101, body=b'\0\x2c'),
        ])
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)
        self.assertCAEqual(rep, cmd=1, dtype=5, p2=ioid)
        if self.sver>=13:
            # Server support dynamic array size
            self.assertCAEqual(rep, p1=1, dcnt=1)
        elif rep.p1==1 and rep.dcnt==0: # RSRV does this
            pass
        elif rep.p1>>3==22: # PCAS does this
            pass
        else:
            self.fail("No match %s"%rep)
        self.assertEqual(rep.body[:4], b'\0\0\0\x2c')

        # cancel subscription
        self.sendTCP([
            Msg(cmd=2, dtype=5, dcnt=0, p1=self.sid, p2=ioid),
        ])

        # wait for confirmation
        rep = self.recvTCP()
        # Note P1 in reply is a CA status code (1==ok)

        self.assertCAEqual(rep, cmd=1, dtype=5, dcnt=0, p1=self.sid, p2=ioid, size=0)


if __name__=='__main__':
    import os
    if 'LOGLEVEL' in os.environ:
        logging.basicConfig(level=logging.getLevelName(os.environ['LOGLEVEL']))
    unittest.main()
