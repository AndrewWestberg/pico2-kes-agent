#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
    cat <<'EOF'
Usage: sh install.sh [--bundle DIRECTORY] [--role primary|backup] [--help]
Before running this script, authenticate it independently with the project
release authority and install.sh.asc. Never trust an unauthenticated download.
A local candidate requires explicit disposable-host acceptance in the manager.
EOF
}
role=primary
bundle=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; usage; exit 0 ;;
        --bundle) [ "$#" -ge 2 ] && [ -z "$bundle" ] || { usage >&2; exit 2; }; bundle=$2; shift 2 ;;
        --role) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; role=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$role" in primary|backup) ;; *) usage >&2; exit 2 ;; esac
[ -t 0 ] && [ -t 1 ] || { echo 'An attended terminal is required.' >&2; exit 3; }
echo 'The bootstrap itself must have been independently authenticated before execution.' >&2
for tool in /usr/bin/python3 /usr/bin/gpg /usr/bin/gpgv /usr/bin/pkexec; do
    [ -x "$tool" ] || { echo "Missing $tool. Install trusted OS prerequisites and authenticate this script before executing it." >&2; exit 4; }
done
[ "$(uname -m)" = x86_64 ] && [ -d /run/systemd/system ] || { echo 'Unsupported host: x86-64 and systemd required.' >&2; exit 4; }
verifier_code=$(cat <<'PY'
import os, selectors, signal, subprocess, time
def bounded_command(command, timeout=30, limit=65536, env=None):
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True, env=env)
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise subprocess.TimeoutExpired(command, timeout)
                chunk = os.read(process.stdout.fileno(), min(65536, limit+1-len(output)))
                if not chunk: break
                output.extend(chunk)
                if len(output) > limit: raise ValueError('command output exceeds bound')
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise subprocess.TimeoutExpired(command, timeout)
        if process.wait(timeout=remaining):
            raise subprocess.CalledProcessError(process.returncode, command)
        return bytes(output)
    except BaseException:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait()
        raise
    finally:
        process.stdout.close()
PY
)
/usr/bin/python3 -I - <<'PY' || { echo 'Unsupported operating system or glibc.' >&2; exit 4; }
import ctypes
data=open('/etc/os-release',encoding='utf-8').read(16385)
if len(data)>16384: raise SystemExit(1)
values={}
for line in data.splitlines():
    if '=' in line:
        k,v=line.split('=',1); values[k]=v.strip('"')
if (values.get('ID'),values.get('VERSION_ID')) not in (('debian','12'),('ubuntu','24.04')): raise SystemExit(1)
libc=ctypes.CDLL(None); libc.gnu_get_libc_version.restype=ctypes.c_char_p
parts=libc.gnu_get_libc_version().decode('ascii').split('.')
if len(parts)<2 or tuple(map(int,parts[:2]))<(2,36): raise SystemExit(1)
PY
if [ -z "$bundle" ]; then
    echo 'Discover the latest published stable release from the project? Type DOWNLOAD to continue:' >&2
    IFS= read -r choice
    [ "$choice" = DOWNLOAD ] || exit 3
    bundle=$(/usr/bin/python3 -I -c "$verifier_code
$(cat <<'PY'
import hashlib, json, os, re, shutil, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request
from pathlib import Path

allowed = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}
def allowed_url(url):
    p = urllib.parse.urlsplit(url)
    return p.scheme == 'https' and p.hostname in allowed and p.username is None and p.password is None and p.port in (None,443)
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl): raise ValueError('untrusted release redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)
opener = urllib.request.build_opener(Redirect())
def fetch(url, limit, out):
    if not allowed_url(url): raise ValueError('untrusted release origin')
    request=urllib.request.Request(url,headers={'User-Agent':'p2kesup-bootstrap'})
    with opener.open(request,timeout=10) as source, open(out,'xb') as dest:
        count=0
        while True:
            chunk=source.read(65536)
            if not chunk: break
            count+=len(chunk)
            if count>limit: raise ValueError('download exceeds bound')
            dest.write(chunk)
def unique(pairs):
    result={}
    for k,v in pairs:
        if k in result: raise ValueError('duplicate manifest key')
        result[k]=v
    return result
work=Path(tempfile.mkdtemp(prefix='p2kesup-release-'))
try:
    fetch('https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases/latest',1048576,work/'release.json')
    release=json.loads((work/'release.json').read_bytes(),object_pairs_hook=unique)
    if release.get('draft') is not False or release.get('prerelease') is not False: raise ValueError('latest release is not stable')
    assets={}
    for a in release.get('assets',[]):
        name=a.get('name'); url=a.get('browser_download_url')
        if name in assets: raise ValueError('duplicate release asset')
        if isinstance(name,str) and isinstance(url,str): assets[name]=url
    for name in ('distribution.json','distribution.json.asc','release-authority.asc'):
        url=assets[name]; p=urllib.parse.urlsplit(url)
        if p.hostname!='github.com' or not p.path.startswith('/AndrewWestberg/pico2-kes-agent/releases/download/'): raise ValueError('untrusted release asset')
        fetch(url,1048576,work/name)
    keyring=work/'authority.gpg'
    bounded_command(['/usr/bin/gpg','--homedir',str(work),'--batch','--no-options','--dearmor','--output',str(keyring),str(work/'release-authority.asc')])
    output=bounded_command(['/usr/bin/gpgv','--homedir',str(work),'--keyring',str(keyring),'--status-fd','1',str(work/'distribution.json.asc'),str(work/'distribution.json')])
    text=output.decode('ascii'); signatures=[x.split() for x in text.splitlines() if x.startswith('[GNUPG:] VALIDSIG ')]
    if len(signatures)!=1 or len(signatures[0])!=12 or signatures[0][2]!='78C0F32094CD02A4BAFA444C684E37A210480F82' or signatures[0][11]!='9FF957E79B5D853544805F4725491F18087931B6' or any('[GNUPG:] '+x in text for x in ('REVKEYSIG','EXPKEYSIG','EXPSIG','BADSIG','ERRSIG')): raise ValueError('unauthorized manifest')
    manifest=json.loads((work/'distribution.json').read_bytes(),object_pairs_hook=unique)
    if manifest.get('schema_version')!=1 or manifest.get('purpose')!='pico2-kes-agent-distribution-v1' or manifest.get('qualification')!='qualified' or manifest.get('release',{}).get('channel')!='stable': raise ValueError('no qualified stable release')
    entries={}
    for item in manifest.get('artifacts',[]):
        name=item.get('path'); size=item.get('size_bytes'); digest=item.get('sha256')
        if not isinstance(name,str) or len(name.encode())>240 or name.startswith('/') or '\\' in name or any(x in ('','.','..') for x in name.split('/')) or any(ord(c)<32 or ord(c)==127 for c in name) or name in entries or type(size)!=int or not 0<=size<=268435456 or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest) or item.get('mode') not in (420,493): raise ValueError('invalid artifact')
        entries[name]=item
    total=sum(x['size_bytes'] for x in entries.values())
    if not entries or len(entries)>256 or total>1073741824 or shutil.disk_usage(work).free < 2*total+2097152: raise ValueError('release bounds or free space')
    archive=assets['distribution.tar']; p=urllib.parse.urlsplit(archive)
    if p.hostname!='github.com' or not p.path.startswith('/AndrewWestberg/pico2-kes-agent/releases/download/'): raise ValueError('untrusted archive origin')
    fetch(archive,1074790400,work/'distribution.tar')
    output=work/'bundle'; output.mkdir(mode=0o700); seen=set()
    with tarfile.open(work/'distribution.tar',mode='r:') as tar:
        for member in tar:
            name=member.name
            if name not in entries or name in seen or not member.isfile() or member.size!=entries[name]['size_bytes']: raise ValueError('unexpected archive member')
            seen.add(name); target=output/name; target.parent.mkdir(parents=True,exist_ok=True)
            source=tar.extractfile(member)
            if source is None: raise ValueError('unreadable archive member')
            digest=hashlib.sha256(); count=0
            with source, open(target,'xb') as dest:
                while True:
                    data=source.read(65536)
                    if not data: break
                    count+=len(data)
                    if count>member.size: raise ValueError('archive size mismatch')
                    digest.update(data); dest.write(data)
            if count!=member.size or digest.hexdigest()!=entries[name]['sha256']: raise ValueError('archive digest mismatch')
            target.chmod(entries[name]['mode'])
    if seen!=set(entries): raise ValueError('incomplete archive')
    shutil.copyfile(work/'distribution.json',output/'distribution.json')
    shutil.copyfile(work/'distribution.json.asc',output/'distribution.json.asc')
    print(output)
except BaseException:
    shutil.rmtree(work,ignore_errors=True)
    raise
PY
)"
    ) || { echo 'Stable release discovery or verification failed.' >&2; exit 4; }
    explicit=no
else
    explicit=yes
fi
bundle=$(realpath -- "$bundle")
script=$(realpath -- "$0")
[ -d "$bundle" ] || { echo 'Bundle directory not found.' >&2; exit 4; }
/usr/bin/python3 -I -c "$verifier_code
$(cat <<'PY'
import hashlib, json, os, stat, subprocess, sys, tempfile
from pathlib import Path
bundle=Path(sys.argv[1]); script=Path(sys.argv[2]); explicit=sys.argv[3]=='yes'
def read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        meta=os.fstat(f.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_size>limit: raise ValueError('unsafe bootstrap input')
        data=f.read(limit+1)
        if len(data)!=meta.st_size: raise ValueError('bootstrap input changed')
        return data
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate manifest key')
        result[key]=value
    return result
with tempfile.TemporaryDirectory(prefix='p2kesup-preverify-') as temp:
    temp=Path(temp)
    for path,name in ((bundle/'distribution.json','distribution.json'),(bundle/'distribution.json.asc','distribution.json.asc'),(bundle/'firmware/release-authority.asc','authority.asc'),(bundle/'install.sh','install.sh'),(bundle/'install.sh.asc','install.sh.asc')):
        (temp/name).write_bytes(read(path,1048576))
    keyring=temp/'authority.gpg'
    bounded_command(['/usr/bin/gpg','--homedir',str(temp),'--batch','--no-options','--dearmor','--output',str(keyring),str(temp/'authority.asc')])
    for name in ('distribution.json','install.sh'):
        output=bounded_command(['/usr/bin/gpgv','--homedir',str(temp),'--keyring',str(keyring),'--status-fd','1',str(temp/(name+'.asc')),str(temp/name)])
        text=output.decode('ascii'); valid=[line.split() for line in text.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if len(valid)!=1 or len(valid[0])!=12 or valid[0][2]!='78C0F32094CD02A4BAFA444C684E37A210480F82' or valid[0][11]!='9FF957E79B5D853544805F4725491F18087931B6' or any('[GNUPG:] '+x in text for x in ('REVKEYSIG','EXPKEYSIG','EXPSIG','BADSIG','ERRSIG')): raise ValueError('unauthorized signature')
    if read(script,1048576)!=(temp/'install.sh').read_bytes(): raise ValueError('running bootstrap differs from signed script')
    manifest=json.loads((temp/'distribution.json').read_bytes(),object_pairs_hook=unique)
    if manifest.get('schema_version')!=1 or manifest.get('purpose')!='pico2-kes-agent-distribution-v1' or manifest.get('qualification') not in ('candidate','qualified') or (not explicit and manifest.get('qualification')!='qualified'): raise ValueError('release admission denied')
    entries=[x for x in manifest.get('artifacts',[]) if isinstance(x,dict) and x.get('path')=='bin/p2kesup']
    if len(entries)!=1: raise ValueError('ambiguous manager')
    binary=read(bundle/'bin/p2kesup',268435456)
    if len(binary)!=entries[0].get('size_bytes') or hashlib.sha256(binary).hexdigest()!=entries[0].get('sha256'): raise ValueError('manager digest mismatch')
PY
)" "$bundle" "$script" "$explicit" || { echo 'Bootstrap authentication failed before privilege handoff.' >&2; exit 4; }
echo 'A polkit authentication agent is required. The privileged verifier will authenticate and protect the selected manager before it runs.' >&2
root_code="$verifier_code
$(cat <<'PY'
import ctypes, hashlib, json, os, re, stat, subprocess, sys, tempfile
from pathlib import Path

bundle = Path(sys.argv[1]); script = Path(sys.argv[2]); explicit = sys.argv[3] == 'yes'
primary = '9FF957E79B5D853544805F4725491F18087931B6'
signer = '78C0F32094CD02A4BAFA444C684E37A210480F82'
def fail(message):
    raise SystemExit(message)
def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
            fail('unsafe or oversized bootstrap input')
        data = f.read(limit + 1)
        if len(data) != st.st_size: fail('bootstrap input changed')
        return data
def unique(pairs):
    result = {}
    for k,v in pairs:
        if k in result: fail('duplicate manifest key')
        result[k] = v
    return result
with tempfile.TemporaryDirectory(prefix='p2kesup-bootstrap-') as tmp:
    tmp = Path(tmp)
    for source, name, limit in [(bundle/'distribution.json','distribution.json',1048576), (bundle/'distribution.json.asc','distribution.json.asc',1048576), (bundle/'firmware/release-authority.asc','authority.asc',1048576), (bundle/'install.sh','install.sh',1048576), (bundle/'install.sh.asc','install.sh.asc',1048576)]:
        (tmp/name).write_bytes(read(source, limit))
    keyring = tmp/'authority.gpg'
    bounded_command(['/usr/bin/gpg','--homedir',str(tmp),'--batch','--no-options','--dearmor','--output',str(keyring),str(tmp/'authority.asc')])
    def signature(name):
        output = bounded_command(['/usr/bin/gpgv','--homedir',str(tmp),'--keyring',str(keyring),'--status-fd','1',str(tmp/(name+'.asc')),str(tmp/name)])
        text=output.decode('ascii'); valid=[line.split() for line in text.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if len(valid)!=1 or len(valid[0])!=12 or valid[0][2]!=signer or valid[0][11]!=primary or any('[GNUPG:] '+bad in text for bad in ('REVKEYSIG','EXPKEYSIG','EXPSIG','BADSIG','ERRSIG')): fail('unauthorized signature')
    signature('distribution.json'); signature('install.sh')
    manifest=json.loads((tmp/'distribution.json').read_bytes(), object_pairs_hook=unique)
    if manifest.get('schema_version') != 1 or manifest.get('purpose') != 'pico2-kes-agent-distribution-v1' or manifest.get('qualification') not in ('candidate','qualified'): fail('unsupported signed distribution')
    if not explicit and manifest['qualification'] != 'qualified': fail('candidate requires explicit --bundle')
    if read(script,1048576) != (tmp/'install.sh').read_bytes(): fail('executing script differs from signed bootstrap')
    os_release={}
    for line in read(Path('/etc/os-release').resolve(strict=True),16384).decode().splitlines():
        if '=' in line:
            k,v=line.split('=',1); os_release[k]=v.strip('"')
    identity=(os_release.get('ID'),os_release.get('VERSION_ID'))
    if identity not in (('debian','12'),('ubuntu','24.04')): fail('unsupported operating system')
    libc=ctypes.CDLL(None); libc.gnu_get_libc_version.restype=ctypes.c_char_p
    version=libc.gnu_get_libc_version().decode('ascii').split('.')
    if len(version)<2 or tuple(map(int,version[:2]))<(2,36): fail('glibc 2.36 or later required')
    platform=manifest.get('platform',{})
    if platform.get('target')!='x86_64-unknown-linux-gnu' or not any((x.get('id'),x.get('version'))==identity for x in platform.get('os',[])): fail('distribution does not support this host')
    components=manifest.get('components'); artifacts=manifest.get('artifacts')
    if not isinstance(components,list) or not isinstance(artifacts,list) or len(artifacts)>256: fail('invalid signed manifest')
    managers=[x for x in components if isinstance(x,dict) and x.get('name')=='manager' and x.get('artifact')=='bin/p2kesup']
    entries=[x for x in artifacts if isinstance(x,dict) and x.get('path')=='bin/p2kesup']
    if len(managers)!=1 or len(entries)!=1: fail('ambiguous manager')
    item=entries[0]; digest=item.get('sha256'); size=item.get('size_bytes')
    if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest) or type(size)!=int or not 0<size<=268435456 or item.get('mode')!=493: fail('invalid manager artifact')
    binary=read(bundle/'bin/p2kesup',268435456)
    if len(binary)!=size or hashlib.sha256(binary).hexdigest()!=digest: fail('manager bytes changed')
    packages=set()
    for requirement in manifest.get('prerequisites',[]):
        if requirement.get('operation')!='install': continue
        for package in requirement.get('packages',[]):
            if (package.get('id'),package.get('version'))==identity:
                for name in package.get('names',[]):
                    if not isinstance(name,str) or not re.fullmatch('[a-z0-9][a-z0-9+.-]*',name): fail('invalid package name')
                    packages.add(name)
    if not packages: fail('signed install prerequisites unavailable')
    missing=[]
    for package in sorted(packages):
        try: installed = bounded_command(['/usr/bin/dpkg-query','-W','-f=${Status}',package]) == b'install ok installed'
        except subprocess.CalledProcessError: installed = False
        if not installed: missing.append(package)
    if missing:
        apt_env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}
        def simulate():
            return bounded_command(['/usr/bin/apt-get','--simulate','install','--',*missing],env=apt_env,limit=1048576)
        proposal=simulate()
        with open('/dev/tty','r+') as tty:
            tty.write('Requested signed distro packages: '+ ' '.join(missing)+'\nExact apt simulation, including dependencies:\n'+proposal.decode('utf-8','backslashreplace')+'\nType INSTALL to approve this proposal: '); tty.flush()
            approval=tty.readline(257)
            if len(approval)>256 or approval.strip()!='INSTALL': fail('prerequisites declined')
            if simulate()!=proposal: fail('apt proposal changed; review again')
            subprocess.run(['/usr/bin/apt-get','install','--',*missing],env=apt_env,stdin=tty,stdout=tty,stderr=tty,check=True)
        for package in missing:
            if bounded_command(['/usr/bin/dpkg-query','-W','-f=${Status}',package]) != b'install ok installed': fail('prerequisite recheck failed')
    for tool in ('/usr/bin/gpg','/usr/bin/gpgv','/usr/bin/python3','/usr/bin/pkexec','/usr/bin/readelf'):
        if not os.path.isfile(tool) or not os.access(tool,os.X_OK): fail('required tool unavailable after installation')
    os.umask(0o022)
    parent=Path('/var/lib/p2kesup')
    for d in (parent, parent/'bootstrap'):
        try: d.mkdir(mode=0o755)
        except FileExistsError: pass
        st=d.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o755: fail('unsafe protected bootstrap directory')
    d=Path(tempfile.mkdtemp(prefix='manager-',dir=parent/'bootstrap')); d.chmod(0o755)
    path=d/'p2kesup'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
    with os.fdopen(fd,'wb') as f:
        f.write(binary); f.flush(); os.fchmod(f.fileno(),0o755); os.fsync(f.fileno())
    for directory in (d,parent/'bootstrap',parent):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)
    print(path)
PY
)"
manager=$(/usr/bin/pkexec /usr/bin/python3 -I -c "$root_code" "$bundle" "$script" "$explicit") || { echo 'Authenticated bootstrap or prerequisites failed.' >&2; exit 4; }
echo 'Bootstrap authenticated. Install through the reviewed manager; no service is implied by the backup role.' >&2
if [ "$role" = backup ]; then
    echo 'After installation reopen with: p2kesup --role backup' >&2
else
    echo 'After installation reopen with: p2kesup' >&2
fi
exec "$manager" --bundle "$bundle" --role "$role"
