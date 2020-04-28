# coding=utf-8
import re
import pytest
import sys
xfail = pytest.mark.xfail


def test_unicode_roundtrip(protocol_real):
    shell_id = protocol_real.open_shell(codepage=65001)
    command_id = protocol_real.run_command(
        shell_id, u'PowerShell', arguments=['-Command', 'Write-Host', u'こんにちは'])

    try:
        std_out, std_err, status_code = protocol_real.get_command_output(
            shell_id, command_id)
        assert status_code == 0
        assert len(std_err) == 0
        # std_out will be returned as UTF-8, but PEP8 won't let us store a
        # UTF-8 string literal, so we'll convert it on the fly
        assert std_out == (u'こんにちは\n'.encode('utf-8'))

    finally:
        protocol_real.cleanup_command(shell_id, command_id)
        protocol_real.close_shell(shell_id)
def test_get_legal_command_output_live_and_cleanup_command(protocol_real):
    if sys.version[0] == '2':
        from StringIO import StringIO
    else:
        from io import StringIO
    import threading

    shell_id = protocol_real.open_shell()
    command_id = protocol_real.run_command(shell_id, 'ping', 'localhost'.split())

    class CmdTask:
        def __init__(self):
            self.stat, self.o_std, self.e_std = None, None, None
            self.o_stream, self.e_stream = StringIO(), StringIO

        def get_response(self):
            self.o_std, self.e_std, self.stat = protocol_real.get_command_output(shell_id, command_id,
                                                                                 out_stream=self.o_stream,
                                                                                 err_stream=self.e_stream)
    tsk = CmdTask()
    threading.Thread(target=tsk.get_response).start()

    # Waiting for the stream to get some input
    while not tsk.o_stream:
        pass

    tmp = tsk.o_stream.getvalue()
    is_different = False

    while tsk.stat is None or tsk.stat != 0:
        if tmp == tsk.o_stream.getvalue():
            is_different = True

    # Checking if ever the stream was updated.
    # assert is_different
    # Checking of the final print to std_out is the same as in the stream
    assert tsk.o_stream.getvalue() == tsk.o_std


def test_get_illegal_command_output_live_and_cleanup_command(protocol_real):
    if sys.version[0] == '2':
        from StringIO import StringIO
    else:
        from io import StringIO

    shell_id = protocol_real.open_shell()
    command_id = protocol_real.run_command(shell_id, 'fake_cmd')
    o_stream, e_stream = StringIO(), StringIO()

    o_std, e_std, stat = protocol_real.get_command_output(shell_id, command_id, out_stream=o_stream,
                                                          err_stream=e_stream)

    # Checking of the final print to std_out is the same as in the stream
    assert stat != 0
    assert e_stream.getvalue() == e_std


def test_open_shell_and_close_shell(protocol_real):
    shell_id = protocol_real.open_shell()
    assert re.match(r'^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$', shell_id)

    protocol_real.close_shell(shell_id)


def test_run_command_with_arguments_and_cleanup_command(protocol_real):
    shell_id = protocol_real.open_shell()
    command_id = protocol_real.run_command(shell_id, 'ipconfig', ['/all'])
    assert re.match(r'^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$', command_id)

    protocol_real.cleanup_command(shell_id, command_id)
    protocol_real.close_shell(shell_id)


def test_run_command_without_arguments_and_cleanup_command(protocol_real):
    shell_id = protocol_real.open_shell()
    command_id = protocol_real.run_command(shell_id, 'hostname')
    assert re.match(r'^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$', command_id)

    protocol_real.cleanup_command(shell_id, command_id)
    protocol_real.close_shell(shell_id)


def test_run_command_with_env(protocol_real):

    shell_id = protocol_real.open_shell(env_vars=dict(TESTENV1='hi mom', TESTENV2='another var'))
    command_id = protocol_real.run_command(shell_id, 'echo', ['%TESTENV1%', '%TESTENV2%'])
    std_out, std_err, status_code = protocol_real.get_command_output(shell_id, command_id)
    assert re.search(b'hi mom another var', std_out)

    protocol_real.cleanup_command(shell_id, command_id)
    protocol_real.close_shell(shell_id)


def test_get_command_output(protocol_real):
    shell_id = protocol_real.open_shell()
    command_id = protocol_real.run_command(shell_id, 'ipconfig', ['/all'])
    std_out, std_err, status_code = protocol_real.get_command_output(
        shell_id, command_id)

    assert status_code == 0
    assert b'Windows IP Configuration' in std_out
    assert len(std_err) == 0

    protocol_real.cleanup_command(shell_id, command_id)
    protocol_real.close_shell(shell_id)


def test_run_command_taking_more_than_operation_timeout_sec(protocol_real):
    shell_id = protocol_real.open_shell()
    command_id = protocol_real.run_command(
        shell_id, 'PowerShell -Command Start-Sleep -s {0}'.format(protocol_real.operation_timeout_sec * 2))
    assert re.match(r'^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$', command_id)
    std_out, std_err, status_code = protocol_real.get_command_output(
        shell_id, command_id)

    assert status_code == 0
    assert len(std_err) == 0

    protocol_real.cleanup_command(shell_id, command_id)
    protocol_real.close_shell(shell_id)


@xfail()
def test_set_timeout(protocol_real):
    raise NotImplementedError()


@xfail()
def test_set_max_env_size(protocol_real):
    raise NotImplementedError()


@xfail()
def test_set_locale(protocol_real):
    raise NotImplementedError()
