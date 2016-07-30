# -*- coding: utf-8 -*-
"""
Created on Sat Jul 30 13:04:26 2016

@author: mdavidsaver
"""

import os, time, errno
import socket, logging
from struct import Struct

_log = logging.getLogger(__name__)

__all__ = [
    'Msg',
    'TestMixinUDP',
    'TestMixinClient',
    'TestMixinServer',
    'TestMixinRunDUT',
]

class Msg(object):
    'A CA message'
    _head = Struct("!HHHHII")
    _head_ext = Struct("!II")
    _sub_body = Struct("!fffH")

    def __init__(self, **kws):
        'Build CA message'
        self.cmd = self.size = self.dtype = self.dcnt = self.p1 = self.p2 = 0
        self.body = kws.pop('body','')
        for K,V in kws.items():
            setattr(self, K, V)
        BL = len(self.body)
        if BL%8:
            self.body = self.body + '\0'*(8-BL%8)
        self.size = len(self.body)
        assert self.size%8==0, self.size

    @classmethod
    def unpack(klass, bytes):
        'Unpack basic (short) CA header'
        I = klass()
        I.cmd, I.size, I.dtype, I.dcnt, I.p1, I.p2 = klass._head.unpack(bytes[:klass._head.size])
        bytes = bytes[klass._head.size:]
        return I, bytes

    def pack(self):
        'Serialize CA message'
        B = self.body or ''
        self.size = len(B)
        H = self._head.pack(self.cmd, self.size, self.dtype, self.dcnt, self.p1, self.p2)
        return H+B

    def __str__(self):
        self.size = len(self.body or '')
        return 'Msg(cmd=%(cmd)d, size=%(size)d, dtype=%(dtype)d, dcnt=%(dcnt)d, p1=%(p1)d, p2=%(p2)d)'%vars(self)
    __repr__ = __str__

class TestMixinUDP(object):
    timeout = 0.5
    def setUp(self):
        S = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        S.bind(('127.0.0.1',0))
        _addr, self.uport = S.getsockname()
        S.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        S.settimeout(self.timeout)
        self.usock = S
        self.addCleanup(self._sock_close)

    def tearDown(self):
        pass # placeholder

    def _sock_close(self):
        for N in ('usock', 'sess', 'server'):
            S = getattr(self, N, None)
            if S:
                S.close()
                setattr(self, N, None)

    def recvUDP(self):
        'Receive one UDP packet and return a list of CA messages'
        pkt, src = self.usock.recvfrom(4096)
        _log.debug("udp -->")
        msg = []
        while len(pkt):
            M, pkt = Msg.unpack(pkt)
            M.body = pkt[:M.size]
            pkt = pkt[M.size:]
            msg.append(M)
            _log.debug("  %s", M)
        return msg

    def sendUDP(self, msg):
        _log.debug("udp <--")
        for M in msg:
            _log.debug("  %s", M)
        pkt = ''.join([M.pack() for M in msg])
        self.usock.sendto(pkt, ('127.0.0.1', self.testport))

    def ensureTCP(self, N):
        'Block until at least N bytes have been received'
        while len(self.rxbuf)<N:
            B = self.sess.recv(1024)
            if len(B)==0:
                break
            self.rxbuf = self.rxbuf+B

    def recvTCP(self):
        'Recieve a single CA message from the TCP client'
        assert self.sess is not None
        self.ensureTCP(Msg._head.size)
        pkt, self.rxbuf = Msg.unpack(self.rxbuf)
        if pkt.size==0xffff or pkt.dcnt==0xffff:
            self.ensureTCP(Msg._head_ext.size)
            pkt.size, pkt.dcnt = Msg._head_ext.unpack(self.rxbuf[:Msg._head_ext.size])
            self.rxbuf = self.rxbuf[Msg._head_ext.size:]
        self.ensureTCP(pkt.size)
        pkt.body, self.rxbuf = self.rxbuf[:pkt.size], self.rxbuf[pkt.size:]
        _log.debug("tcp --> %s", pkt)
        return pkt

    def sendTCP(self, msg):
        assert self.sess is not None
        for pkt in msg:
            _log.debug("tcp <-- %s", pkt)
        pkt = ''.join([M.pack() for M in msg])
        self.sess.sendall(pkt)

    def closeTCP(self):
        _log.debug("TCP close")
        assert self.sess is not None
        assert len(self.rxbuf)==0, repr(self.rxbuf)
        self.sess.close()
        self.sess = None

    def assertCAEqual(self, msg, **kws):
        match=True
        for K,V in kws.items():
            if not hasattr(msg, K):
                match  = False
            else:
                match &= V==getattr(msg, K)
        if not match:
            raise self.failureException("%s doesn't match %s"%(msg, kws))

class TestMixinServer(TestMixinUDP):
    def setUp(self):
        TestMixinUDP.setUp(self)
        S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        S.bind(('127.0.0.1',0))
        _addr, self.tport = S.getsockname()

        S.settimeout(self.timeout)
        self.server = S
        self.sess = None
        self.rxbuf = ''
        self._socks.extend(['server','sess'])

    def waitClient(self):
        'Wait for a TCP client to connect'
        if self.sess is not None:
            raise RuntimeError("Client already connected")

        S, peer = self.server.accept()
        _log.debug("%s >>>", peer)
        self.sess = S

class TestMixinClient(TestMixinUDP):
    def setUp(self):
        TestMixinUDP.setUp(self)
        self.sess = None
        self.rxbuf = ''

    def connectTCP(self):
        peer = ('127.0.0.1', self.testport)
        _log.debug("TCP connect %s", peer)
        S = socket.create_connection(peer, timeout=self.timeout)
        S.settimeout(self.timeout)
        self.sess = S

class TestMixinRunDUT(object):
    testport = None
    testname = None
    dut = None
    def setUp(self):
        if self.testport is None:
            import random
            self.testport = random.randint(7890, 7899)

        env = os.environ.copy()
        env.update({
            'IOCSH_HISTEDIT_DISABLE':'YES',
            'EPICS_CA_ADDR_LIST':'127.0.0.1',
            'EPICS_CA_AUTO_ADDR_LIST':'NO',
            'EPICS_CA_SERVER_PORT':str(self.testport),
        })

        if self.testname is not None:
            _log.info("Setup for test %s", self.testname)
            env['TEST_NAME'] = self.testname

        if self.dut is None:
            self.dut = os.environ['DUT']

        from tempfile import TemporaryFile
        from subprocess import Popen, PIPE, STDOUT

        self.SP_cap = TemporaryFile() # capture stdout and stderr

        self.SP = Popen(self.dut, shell=True, env=env,
                        stdin=PIPE, stderr=STDOUT, stdout=self.SP_cap)
        self.addCleanup(self._stop_dut)

        # wait for CA server startup
        ST = None
        for i in range(20):
            time.sleep(0.1)
            try:
                ST = socket.create_connection(('127.0.0.1', self.testport), timeout=0.1)
            except socket.timeout:
                continue
            except socket.error as e:
                if e.errno!=errno.ECONNREFUSED:
                    raise
                continue
            except:
                raise
            break
        if ST is None:
            self.SP.kill()
            self.fail("timeout waiting for DUT to start TCP server")
        ST.close()

    def tearDown(self):
        pass # placeholder

    def _stop_dut(self):
        self.SP.terminate()
        for i in range(10):
            if self.SP.poll() is not None:
                break
            time.sleep(0.1)
        if self.SP.returncode is None:
            _log.warn("Killed '%s'", self.dut)
            self.SP.kill()
            self.SP.wait()
        self.SP.wait()
        time.sleep(0.1) # kludge to wait for IOC errlog to flush...
        self.SP_cap.seek(0)
        _log.info(self.SP_cap.read())
        self.SP_cap.close()
        #self.assertEqual(self.SP.returncode, 0)

class TestClient(TestMixinClient, TestMixinRunDUT):
    def setUp(self):
        TestMixinRunDUT.setUp(self)
        TestMixinClient.setUp(self)
    def tearDown(self):
        TestMixinRunDUT.tearDown(self)
        TestMixinClient.tearDown(self)
