# -*- coding: utf-8 -*-
"""
Created on Sat Jul 30 13:04:26 2016

@author: mdavidsaver
"""

from __future__ import print_function
import sys, os, time, errno, signal, threading
import socket, logging, shutil
from struct import Struct

_log = logging.getLogger(__name__)

__all__ = [
    'Msg',
    'TestMixinUDP',
    'TestMixinClient',
    'TestMixinServer',
    'TestMixinRunServer',
]

_msgname = {
    0 :'VERSION          ',
    1 :'EVENT_ADD        ',
    2 :'EVENT_CANCEL     ',
    3 :'READ             ',
    4 :'WRITE            ',
    5 :'SNAPSHOT         ',
    6 :'SEARCH           ',
    7 :'BUILD            ',
    8 :'EVENTS_ON        ',
    9 :'EVENTS_OFF       ',
    10:'READ_SYNC        ',
    11:'ERROR            ',
    12:'CLEAR_CHANNEL    ',
    13:'RSRV_IS_IP       ',
    14:'NOT_FOUND        ',
    15:'READ_NOTIFY      ',
    16:'READ_BUILD       ',
    17:'REPEATER_CONFIRM ',
    18:'CREATE_CHAN      ',
    19:'WRITE_NOFITY     ',
    20:'CLIENT_NAME      ',
    21:'HOST_NAME        ',
    22:'ACCESS_RIGHTS    ',
    23:'ECHO             ',
    24:'REPEATER_REGISTER',
    25:'SIGNAL           ',
    26:'CREATE_CH_FAIL   ',
    27:'SERVER_DISCONN   ',
}

class TempDir(object):
    def __init__(self):
        self.dir = None
        self.open()
    def open(self):
        from tempfile import mkdtemp
        if not self.dir:
            self.dir = mkdtemp()
    def close(self):
        if self.dir:
            shutil.rmtree(self.dir)
            self.dir = None
    def __enter__(self):
        self.open()
        return self
    def __exit__(self,A,B,C):
        self.close()
    def __del__(self):
        self.close()

class SpamThread(threading.Thread):
    def __init__(self, fd):
        threading.Thread.__init__(self)
        self._pr, self._pw = os.pipe()
        self.fd = fd
    def join(self):
        os.write(self._pw, b' ')
        ret = threading.Thread.join(self)
        os.close(self._pr)
        os.close(self._pw)
        return ret
    def run(self):
        import select
        while True:
            R, W, X = select.select([self._pr, self.fd], [], [])
            if self.fd in R:
                try:
                    B = os.read(self.fd, 1024)
                except OSError as e:
                    # can get EIO if the child has already
                    # terminated.
                    if e.errno==errno.EIO:
                        return
                    raise
                if len(B):
                    print(B)
            if self._pr in R:
                break

class Msg(object):
    'A CA message'
    _head = Struct("!HHHHII")
    _head_ext = Struct("!II")
    _sub_body = Struct("!fffH")

    def __init__(self, body=b'', **kws):
        'Build CA message'
        self.cmd = self.size = self.dtype = self.dcnt = self.p1 = self.p2 = 0
        self.body = body
        for K,V in kws.items():
            setattr(self, K, V)
        BL = len(self.body)
        if BL%8:
            self.body = self.body + b'\0'*(8-BL%8)
        self.size = len(self.body)
        assert self.size%8==0, self.size

    @classmethod
    def unpack(klass, bytes_):
        'Unpack basic (short) CA header'
        I = klass()
        I.cmd, I.size, I.dtype, I.dcnt, I.p1, I.p2 = klass._head.unpack(bytes_[:klass._head.size])
        return I, bytes_[klass._head.size:]

    def pack(self):
        'Serialize CA message'
        B = self.body or b''
        self.size = len(B)
        H = self._head.pack(self.cmd, self.size, self.dtype, self.dcnt, self.p1, self.p2)
        return H + B

    def __str__(self):
        S = vars(self)
        S['cmdname']='%s(%2d)'%(_msgname.get(self.cmd, 'UNKNOWN'), self.cmd)
        self.size = len(self.body or '')
        S['body'] = self.body[:16] + (b'...' if self.size>16 else b'')
        return ('Msg(cmd=%(cmdname)s, size=%(size)d, dtype=%(dtype)d, dcnt=%(dcnt)d, p1=%(p1)d, '
                'p2=%(p2)d, body="%(body)s")' % S)

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
        pkt = b''.join(M.pack() for M in msg)
        self.usock.sendto(pkt, ('127.0.0.1', self.testport))

    def ensureTCP(self, N):
        'Block until at least N bytes have been received'
        while len(self.rxbuf)<N:
            B = self.sess.recv(1024)
            if len(B)==0:
                return False
            self.rxbuf += B
        return True

    def recvTCP(self):
        'Recieve a single CA message from the TCP client'
        assert self.sess is not None
        if not self.ensureTCP(Msg._head.size):
            _log.debug("tcp --> Closed")
            return None
        pkt, self.rxbuf = Msg.unpack(self.rxbuf)
        if pkt.size==0xffff or pkt.dcnt==0xffff:
            self.ensureTCP(Msg._head_ext.size)
            pkt.size, pkt.dcnt = Msg._head_ext.unpack(self.rxbuf[:Msg._head_ext.size])
            self.rxbuf = self.rxbuf[Msg._head_ext.size:]
        if not self.ensureTCP(pkt.size):
            raise RuntimeError("Truncated message %s"%pkt)
        pkt.body, self.rxbuf = self.rxbuf[:pkt.size], self.rxbuf[pkt.size:]
        _log.debug("tcp --> %s", pkt)
        return pkt

    def sendTCP(self, msg):
        assert self.sess is not None
        for pkt in msg:
            _log.debug("tcp <-- %s", pkt)
        pkt = b''.join(M.pack() for M in msg)
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
        self.rxbuf = b''
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
        self.rxbuf = b''

    def connectTCP(self):
        peer = ('127.0.0.1', self.testport)
        _log.debug("TCP connect %s", peer)
        S = socket.create_connection(peer, timeout=self.timeout)
        S.settimeout(self.timeout)
        self.sess = S

class TestMixinRunServer(object):
    testport = None
    testname = None
    dut = None

    def _check_test_port(self):
        # lousy hack num. 1
        # check to see that the TCP port where we will run the server
        # is unused.
        for i in range(10):
            try:
                ST = socket.create_connection(('127.0.0.1', self.testport), timeout=0.1)
                ST.close()
                if i==9:
                    self.fail("Another server is already running on port %d"%self.testport)
                else:
                    time.sleep(0.2)
            except socket.timeout:
                break
            except socket.error as e:
                self.assertEqual(e.errno, errno.ECONNREFUSED)
                break

    def setUp(self):
        if self.testport is None:
            import random
            if 'TESTPORT' in os.environ:
                self.testport = int(os.environ['TESTPORT'])
            else:
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
            self.dut = os.environ.get('DUT', '')

        if self.dut:
            self._check_test_port()
            self._spawn_dut(env)

    def _spawn_dut(self, env):
        self.TDIR = TempDir()
        tdir = self.TDIR.dir

        self._child, self._child_fd = os.forkpty()
        if self._child==0:
            # Child process
            os.chdir(tdir)
            try:
                os.execve('/bin/sh', ['/bin/sh','-c', self.dut], env)
            finally:
                os.abort() # never reached (we hope)

        # lousy hack num. 1.5
        # can't just dup() our stdout to child since
        # some test runners (nose) capture "stdout"
        # by replacing sys.stdout with StringIO
        # So we start a child thread to echo
        # to sys.stdout
        self.SP = SpamThread(fd=self._child_fd)
        self.SP.start()

        self.addCleanup(self._stop_dut)

        # lousy hack num. 2
        # wait for CA server startup
        ST = None
        for i in range(20):
            time.sleep(0.1)
            try:
                ST = socket.create_connection(('127.0.0.1', self.testport), timeout=0.1)
                break
            except socket.timeout:
                continue
            except socket.error as e:
                if e.errno!=errno.ECONNREFUSED:
                    raise
                continue
            except Exception:
                raise
        if ST is None:
            self.fail("timeout waiting for DUT to start TCP server")
        ST.close()

    def tearDown(self):
        pass # placeholder

    def _stop_dut(self):
        os.kill(self._child, signal.SIGKILL)
        os.waitpid(self._child, 0)
        self.SP.join()
        try:
            os.close(self._child_fd)
        except:
            pass
        #os.close(self._child_fd)
        self.TDIR.close()
        return

        os.kill(self._child, signal.SIGTERM)
        ret = None
        for i in range(10):
            try:
                pid, ret, _rusg = os.wait3(os.WNOHANG)
                #assert self._child==pid, (self._child, pid)
                break
            except OSError as e:
                if e.errno!=errno.ECHILD:
                    raise
            if self.SP.poll() is not None:
                break
            time.sleep(0.1)
        if ret is None:
            _log.warn("Killed '%s'", self.dut)
            os.kill(self._child, signal.SIGKILL)
            os.wait()

        os.close(self._child_fd)

        self.TDIR.close()
        #self.assertEqual(self.SP.returncode, 0)

class TestClient(TestMixinClient, TestMixinRunServer):
    def setUp(self):
        TestMixinRunServer.setUp(self)
        TestMixinClient.setUp(self)
    def tearDown(self):
        TestMixinRunServer.tearDown(self)
        TestMixinClient.tearDown(self)
