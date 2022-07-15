
from __future__ import print_function, unicode_literals
import sys
from collections import namedtuple
import argparse
import ctypes
from functools import partial
import os
import platform
import re
import subprocess
import tempfile
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
try:
    from urllib.request import urlretrieve
except ImportError:
    from urllib import urlretrieveя

if sys.platform != 'win32':
    sys.exit('This script is meant to be run on a Windows machine.'
             ' Only Windows machines are vulnerable to WCry.')



OsVersions = namedtuple('OsVersions',
                        ['xp',             # Windows XP
                         'xpe',            # Windows XP Embedded
                         'xpwes09_pos09',  # Windows XP Embedded; WES09 & POSReady 2009
                         's2003',          # Windows Server 2003 (& Windows XP x64)
                         'vista_s2008',    # Windows Vista & Windows Server 2008
                         'win7_2008r2',    # Windows 7 & Windows Server 2008 R2
                         'win8',           # Windows 8
                         'wine8s_s2012',   # Windows Embedded 8 Standard & Windows Server 2012
                         'win81_s2012r2',  # Windows 8.1 & Windows Server 2012 R2
                         'win10_s2016'])   # Windows 10 & Windows Server 2016



REQUIRED_KB = OsVersions(
    ['KB4012598'],  # xp
    ['KB4012598'],  # xpe
    ['KB4012598'],  # xpwes09_pos09
    ['KB4012598'],  # s2003
    ['KB4012598'],  # vista_s2008
    ['KB4012212', 'KB4012215'],  # win7_2008r2
    ['KB4012598'],  # win8
    ['KB4012214', 'KB4012217'],  # s2012
    ['KB4012213', 'KB4012216'],  # win81_s2012r2
    ['KB4012606', 'KB4013198', 'KB4013429', 'KB4015438',  # win10_s2016
     'KB4016635', 'KB4015217', 'KB4019472']
)


KB_DOWNLOAD = OsVersions(
    {  # xp:
        'x86': 'http://download.windowsupdate.com/d/csa/csa/secu/2017/02/windowsxp-kb4012598-x86-custom-enu_eceb7d5023bbb23c0dc633e46b9c2f14fa6ee9dd.exe',
    },
    {  # xpe:
        'x86': 'http://download.windowsupdate.com/c/csa/csa/secu/2017/02/windowsxp-kb4012598-x86-embedded-custom-enu_8f2c266f83a7e1b100ddb9acd4a6a3ab5ecd4059.exe',
    },
    {  # xpwes09_pos09:
        'x86': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windowsxp-kb4012598-x86-embedded-enu_9515c11bc77e39695b83cb6f0e41119387580e30.exe',
    },
    {  # s2003
        'x86': 'http://download.windowsupdate.com/c/csa/csa/secu/2017/02/windowsserver2003-kb4012598-x86-custom-enu_f617caf6e7ee6f43abe4b386cb1d26b3318693cf.exe',
        'x64': 'http://download.windowsupdate.com/d/csa/csa/secu/2017/02/windowsserver2003-kb4012598-x64-custom-enu_f24d8723f246145524b9030e4752c96430981211.exe',
    },
    {  # vista_s2008:
        'x86': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x86_13e9b3d77ba5599764c296075a796c16a85c745c.msu',
        'x64': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu',
    },
    {  # win7_2008r2
        'x86': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x86_6bb04d3971bb58ae4bac44219e7169812914df3f.msu',
        'x64': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu',
    },
    {  # win8
        'x86': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows8-rt-kb4012598-x86_a0f1c953a24dd042acc540c59b339f55fb18f594.msu',
        'x64': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows8-rt-kb4012598-x64_f05841d2e94197c2dca4457f1b895e8f632b7f8e.msu',
    },
    {  # s2012
        'x86': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x86_5e7e78f67d65838d198aa881a87a31345952d78e.msu',
        'x64': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x64_b14951d29cb4fd880948f5204d54721e64c9942b.msu',
    },
    {  # win81_s2012r2
        'x86': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x86_e118939b397bc983971c88d9c9ecc8cbec471b05.msu',
        'x64': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu',
    },
)



if 'raw_input' in dir(__builtins__):
    input = raw_input

def os_id_index():

def os_id_field_name():
    return OsVersions._fields[os_id_index()]

ProcessInfo = namedtuple('ProcessInfo', ['returncode', 'stdout', 'stderr'])
_decode = partial(bytes.decode, encoding='utf-8')

def run(popen_args):
    proc = subprocess.Popen(popen_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    proc_info = ProcessInfo(proc.returncode, _decode(stdout), _decode(stderr))
    return proc_info

def _strip_to_kb(kb_string):
    match = re.match('KB\d+', kb_string)
    return match.group() if match else None

def _only_kbs(hotfixids):
    for id_ in hotfixids:
        kb = _strip_to_kb(id_)
        if kb:
            yield kb

def list_kbs():
    cmd = ['wmic', 'qfe', 'get', 'hotfixid']
    proc_info = run(cmd)
    hotfixids = proc_info.stdout.split()
    return list(_only_kbs(hotfixids))

def check_installed_kbs():
    print('Checking if a KB with a fix is installed...', end=' ')
    required_kbs = REQUIRED_KB[os_id_index()]
    installed_kbs = list_kbs()
    def kb_found(required_one, all_installed):
        return required_one in all_installed

    fix_installed = any(kb_found(required_one, installed_kbs)
                        for required_one in required_kbs)
    print('yes' if fix_installed else 'no')
    return fix_installed

def _is_powershell_cmdlet_available(cmdlet):
    cmd = ['PowerShell', '-Command',
           'Write-Host',
           '$([bool](Get-Command ' + cmdlet + ' -ErrorAction SilentlyContinue))']
    proc_info = run(cmd)
    return proc_info.stdout.strip().lower() == 'true'

def can_check_smb_v1():
    return _is_powershell_cmdlet_available('Get-SmbServerConfiguration')


def check_smb_v1_powershell():
    cmd = ['PowerShell', '-Command',
           'Get-SmbServerConfiguration | Select EnableSMB1Protocol']
    proc_info = run(cmd)
    if proc_info.stderr:
        sys.stderr.write('Error:\r\n' + proc_info.stderr)
        sys.exit(1)
    return proc_info.stdout.split()[2].strip().lower() == 'false'

def check_smb_v1_registry():
    cmd = ['PowerShell', '-Command',
           'Get-ItemProperty'
           ' -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"'
           ' | Select SMB1']
    proc_info = run(cmd)
    result = proc_info.stdout.split()
    if len(result) >= 3:
        enabled = bool(int(result[2].strip()))
    else:
        enabled = True
    return not enabled


def check_smb_v1():
    print('Checking if the SMB v1 protocol is disabled...', end=' ')
    if can_check_smb_v1():
        smb_v1_disabled = check_smb_v1_powershell()
    else:
        smb_v1_disabled = check_smb_v1_registry()
    print('yes' if smb_v1_disabled else 'no')
    return smb_v1_disabled


def can_set_smb_v1():
    return _is_powershell_cmdlet_available('Set-SmbServerConfiguration')


def set_smb_v1_powershell(enable):
    enable = '$true' if enable else '$false'
    cmd = ['PowerShell', '-Command',
           'Set-SmbServerConfiguration', '-EnableSMB1Protocol', enable,
           '-Confirm:$false']

    proc_info = run(cmd)
    if proc_info.stderr:
        print()
        sys.stderr.write('Error:' + proc_info.stderr)
        sys.exit(1)
    print(proc_info.stdout)


def set_smb_v1_registry(enable):
    enable = '1' if enable else '0'
    cmd = ['PowerShell', '-Command',
           'Set-ItemProperty',
           '-Path', 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
           'SMB1', '-Type', 'DWORD', '-Value', enable, '-Force']
    proc_info = run(cmd)
    if proc_info.stderr:
        print()
        sys.stderr.write('Error:' + proc_info.stderr)
        sys.exit(1)
    print(proc_info.stdout)

def set_smb_v1(enable):
    if can_set_smb_v1():
        set_smb_v1_powershell(enable)
    else:
        set_smb_v1_registry(enable)
    if not enable:
        print('The SMBv1 protocol has been disabled.'
              ' The system is no longer vulnerable.')
    else:
        print('The SMBv1 protocol has been enabled.'
              'This can make the system vulnerable, if the security hole is unpatched.')

def _get_system_root():
    if sys.version_info[0] == 2:
        return _decode(os.environ.get('SystemRoot', b'C:\\Windows'))
    return os.environ.get('SystemRoot', 'C:\\Windows')


def am_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        try:
            os.listdir(os.path.join([_get_system_root(),'temp']))
            return True
        except PermissionError:
            return False
        except:
            return False


def run_as_admin(extra_args=None):
    if not am_admin():
        try:
            print('Restarting and requesting admin privileges.')
            args = sys.argv
            if extra_args:
                args = args + extra_args
            exe, args = sys.executable, ' '.join(args)
            if sys.version_info[0] == 2:
                exe = _decode(exe)
            ctypes.windll.shell32.ShellExecuteW(None, 'Runas', exe, args, None, 1)
            sys.exit()
        except Exception as e:
            print(e)
            msg = (')
            sys.exit(msg)

def check():
    fix_installed = check_installed_kbs()
    smb_v1_disabled = check_smb_v1()
    not_vulnerable = fix_installed or smb_v1_disabled
    print('The system is {}vulnerable.'.format('not ' if not_vulnerable else ''))
    return not_vulnerable

def mitigate():
    if check():
        sys.exit()
    print('Trying to turn off SMBv1, this may require a rerun with admin privileges...')
    run_as_admin()
    set_smb_v1(False)

def _get_os_arch():
    return 'x64' if platform.machine().endswith('64') else 'x86'

def fix(download_directory=None):
    if check():
        sys.exit()
    if os_id_field_name() == 'win10_s2016':
        sys.exit('Downloading and installing an update for Windows 10 or'
                 ' Windows Server 2016 is currently not supported.'
                 ' Please enable automatic updates instead.')
    print('Trying to get an update for your system...')
    kb_download_url = KB_DOWNLOAD[os_id_index()][_get_os_arch()]
    kb_file_name = urlparse(kb_download_url).path.split('/')[-1]
    if not download_directory:
        download_directory = tempfile.gettempdir()
    kb_absolute_path = os.path.join(download_directory, kb_file_name)
    if not os.path.exists(kb_absolute_path):
        try:
            urlretrieve(kb_download_url, kb_absolute_path)
            print("The KB update has been downloaded to: " + kb_absolute_path)
        except Exception as e:
            sys.stderr.write('Error:' + e)
            sys.exit('Unable to download the KB update for your system.')
    else:
        msg = "Using KB update '{}' in directory '{}'.".format(
            kb_file_name, os.path.abspath(download_directory))
        print(msg)
    if kb_file_name.endswith('.exe'):

        proc_info = run([kb_absolute_path])
    elif kb_file_name.endswith('.msu'):
        run_as_admin(['--download-directory', download_directory])
        inst_exe = os.path.join(_get_system_root(), 'system32', 'wusa.exe')
        if not os.path.exists(inst_exe):
            sys.exit("Windows Update Standalone Installer not found."
                     " You will have to find a way to install the file"
                     " '{}' manually".format(kb_absolute_path))
        proc_info = run([inst_exe, kb_absolute_path])
    if proc_info.stderr:
        sys.stderr.write(proc_info)
    print(proc_info.stdout)


def cli_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--check', action='store_true',
                        help="check if the system is vulnerable to WCry")
    parser.add_argument('-m', '--mitigate', action='store_true',
                        help="mitigate the system's vulnerability by disabling the"
                             " SMBv1 protocol, if necessary; implies --check")
    parser.add_argument('-f', '--fix', action='store_true')
    parser.add_argument('--download-directory',
                        help="Optionally specify a directory where the Microsoft"
                             " KB update is saved when using --fix")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()

def main():
    try:
        args = cli_args()
        if args.check and not args.mitigate and not args.fix:
            check()
        elif args.mitigate:
            mitigate()
        elif args.fix:
            fix(args.download_directory)
        input('\r\nDone. Press any key to exit.')
    except Exception as e:
        sys.exit(e)


if __name__ == '__main__':
    main()
