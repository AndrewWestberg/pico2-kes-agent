#!/bin/sh
main() {
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
    cat <<'EOF'
Usage: sh install.sh [--version TAG | --bundle DIRECTORY] [--role primary|backup] [--help]
       sh install.sh (--version TAG | --bundle DIRECTORY) --recovery-plan PATH
Without --version or --bundle, install the latest approved stable release.
An explicit version or local bundle may contain a candidate requiring attended review.
--recovery-plan is only for signed bootstrap recovery of an original host-security operation.
EOF
}
role=primary
bundle=
version=
recovery_plan=
role_seen=no
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; usage; exit 0 ;;
        --bundle) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$bundle" ] && [ -z "$version" ] || { usage >&2; exit 2; }; bundle=$2; shift 2 ;;
        --version) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$version" ] && [ -z "$bundle" ] || { usage >&2; exit 2; }; version=$2; shift 2 ;;
        --recovery-plan) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$recovery_plan" ] || { usage >&2; exit 2; }; recovery_plan=$2; shift 2 ;;
        --role) [ "$#" -ge 2 ] && [ "$role_seen" = no ] || { usage >&2; exit 2; }; role=$2; role_seen=yes; shift 2 ;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$role" in primary|backup) ;; *) usage >&2; exit 2 ;; esac
case "$version" in *[!a-zA-Z0-9._+-]*|[-.+]*) echo 'Invalid release tag.' >&2; exit 2 ;; esac
if [ -n "$recovery_plan" ]; then
    [ -n "$bundle" ] || [ -n "$version" ] || { usage >&2; exit 2; }
    [ "$role_seen" = no ] || { usage >&2; exit 2; }
    recovery_plan=$(realpath -- "$recovery_plan") || exit 2
fi
if ! ( : </dev/tty ) 2>/dev/null; then
    echo 'An attended controlling terminal is required.' >&2; exit 3
fi
exec 3<>/dev/tty
[ "$(uname -m)" = x86_64 ] && [ -d /run/systemd/system ] || { echo 'Unsupported host: x86-64 and systemd required.' >&2; exit 4; }
[ -r /etc/os-release ] || { echo 'Unsupported operating system.' >&2; exit 4; }
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in debian:12|ubuntu:24.04|ubuntu:26.04) ;; *) echo 'Unsupported operating system.' >&2; exit 4 ;; esac
libc=$(/usr/bin/getconf GNU_LIBC_VERSION 2>/dev/null) || { echo 'Unsupported libc.' >&2; exit 4; }
case "$libc" in glibc\ 2.*) minor=${libc#glibc 2.}; case "$minor" in *[!0-9]*|'') echo 'Unsupported libc.' >&2; exit 4 ;; esac; [ "$minor" -ge 36 ] || { echo 'glibc 2.36 or later required.' >&2; exit 4; } ;; *) echo 'Unsupported libc.' >&2; exit 4 ;; esac
[ -x /usr/bin/apt-get ] && [ -x /usr/bin/dpkg-query ] || { echo 'Trusted apt is required.' >&2; exit 4; }
if [ "$(id -u)" -ne 0 ] && [ ! -x /usr/bin/sudo ]; then
    echo 'sudo is required for non-root installation. Install sudo as root, then retry from a terminal, or run the installer as root in a terminal.' >&2
    exit 4
fi
missing=
for pair in python3:python3 gpg:gnupg gpgv:gpgv openssl:openssl sudo:sudo readelf:binutils; do
    tool=${pair%%:*}; package=${pair#*:}
    [ -x "/usr/bin/$tool" ] || missing="$missing $package"
done
[ -n "$bundle" ] || [ -s /etc/ssl/certs/ca-certificates.crt ] || missing="$missing ca-certificates"
if [ -n "$missing" ]; then
    if [ "$(id -u)" -eq 0 ]; then elevate=none
    else elevate=sudo
    fi
    printf 'Missing required software:%s\nRefresh the system package lists to find it? [y/N] ' "$missing" >&3
    IFS= read -r choice <&3 || exit 3
    case "$choice" in y|Y|yes|YES|Yes) ;; *) echo 'Package-list refresh declined.' >&2; exit 3 ;; esac
    case "$elevate" in
        none) /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/apt-get update <&3 >&3 2>&3 ;;
        sudo) /usr/bin/sudo -- /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/apt-get update <&3 >&3 2>&3 ;;
    esac || { echo 'Package-index refresh failed.' >&2; exit 4; }
    proposal=$(/usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/apt-get --simulate install -- $missing) || { echo 'Prerequisite simulation failed.' >&2; exit 4; }
    printf 'Install the missing software and its system dependencies? This changes packages on this computer. [y/N] ' >&3
    IFS= read -r choice <&3 || exit 3
    case "$choice" in y|Y|yes|YES|Yes) ;; *) echo 'Prerequisites declined.' >&2; exit 3 ;; esac
    [ "$(/usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/apt-get --simulate install -- $missing)" = "$proposal" ] || { echo 'The package changes have changed; restart the installer to review them again.' >&2; exit 4; }
    case "$elevate" in
        none) /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/apt-get install -- $missing <&3 >&3 2>&3 ;;
        sudo) /usr/bin/sudo -- /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/bin/apt-get install -- $missing <&3 >&3 2>&3 ;;
    esac || { echo 'Prerequisite installation failed.' >&2; exit 4; }
    for tool in python3 gpg gpgv openssl sudo readelf; do
        [ -x "/usr/bin/$tool" ] || { echo "Prerequisite $tool unavailable." >&2; exit 4; }
    done
    [ -n "$bundle" ] || [ -s /etc/ssl/certs/ca-certificates.crt ] || { echo 'TLS certificates unavailable.' >&2; exit 4; }
fi
if [ -n "$recovery_plan" ]; then
    /usr/bin/python3 -I - "$recovery_plan" <<'PY' || { echo 'Expected a host-security bootstrap recovery plan.' >&2; exit 2; }
import json, os, stat, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, 'rb') as f:
    st = os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_size > 262144: raise SystemExit(1)
    plan = json.load(f)
action = plan.get('action', {})
if action.get('action') != 'host_security_recovery' or not action.get('bootstrap') or not action.get('bootstrap_manifest_digest'):
    raise SystemExit(1)
PY
fi
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
def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate JSON key')
        result[key] = value
    return result
def authenticate_authority(directory):
    import json
    keyring = directory/'authority.gpg'
    bounded_command(['/usr/bin/gpg','--homedir',str(directory),'--batch','--no-options','--dearmor','--output',str(keyring),str(directory/'authority.asc')])
    output = bounded_command(['/usr/bin/gpgv','--homedir',str(directory),'--keyring',str(keyring),'--status-fd','1',str(directory/'distribution-authority.json.asc'),str(directory/'distribution-authority.json')])
    text = output.decode('ascii'); valid = [line.split() for line in text.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    if len(valid)!=1 or len(valid[0])!=12 or valid[0][2]!='78C0F32094CD02A4BAFA444C684E37A210480F82' or valid[0][11]!='9FF957E79B5D853544805F4725491F18087931B6' or any('[GNUPG:] '+bad in text for bad in ('REVKEYSIG','EXPKEYSIG','EXPSIG','BADSIG','ERRSIG')): raise ValueError('unauthorized distribution authority')
    authority = json.loads((directory/'distribution-authority.json').read_bytes(), object_pairs_hook=unique_object)
    if not isinstance(authority,dict) or set(authority)!={'schema_version','purpose','project','algorithm','public_key_pem'} or type(authority['schema_version']) is not int or authority['schema_version']!=1 or authority['purpose']!='pico2-kes-agent-distribution-authority-v1' or authority['project']!='https://github.com/AndrewWestberg/pico2-kes-agent' or authority['algorithm']!='secp256k1' or not isinstance(authority['public_key_pem'],str): raise ValueError('invalid distribution authority')
    key = directory/'distribution-public.pem'
    key.write_bytes(authority['public_key_pem'].encode('ascii'))
    bounded_command(['/usr/bin/openssl','pkey','-pubin','-in',str(key),'-pubcheck','-noout'])
    der = bounded_command(['/usr/bin/openssl','pkey','-pubin','-in',str(key),'-outform','DER'])
    prefix = bytes.fromhex('3056301006072a8648ce3d020106052b8104000a03420004')
    if len(der)!=len(prefix)+64 or not der.startswith(prefix): raise ValueError('invalid distribution public key')
    return key
def distribution_signature(directory, key, name, purpose):
    if purpose not in ('pico2-kes-agent-distribution-v1','pico2-kes-agent-bootstrap-v1'): raise ValueError('invalid signature purpose')
    signed = directory/'signed-input'
    signed.write_bytes(purpose.encode('ascii')+b'\n'+(directory/name).read_bytes())
    bounded_command(['/usr/bin/openssl','dgst','-sha256','-verify',str(key),'-signature',str(directory/(name+'.sig')),str(signed)])
def bind_bootstrap(manifest, directory):
    import hashlib
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts,list): raise ValueError('invalid artifact inventory')
    for name, local in (('distribution-authority.json','distribution-authority.json'),('distribution-authority.json.asc','distribution-authority.json.asc'),('firmware/release-authority.asc','authority.asc'),('install.sh','install.sh'),('install.sh.sig','install.sh.sig')):
        matches = [item for item in artifacts if isinstance(item,dict) and item.get('path')==name]
        if len(matches)!=1: raise ValueError('missing or duplicate bootstrap artifact')
        item = matches[0]; data = (directory/local).read_bytes()
        if type(item.get('size_bytes')) is not int or item['size_bytes']!=len(data) or item.get('sha256')!=hashlib.sha256(data).hexdigest() or (item.get('mode') not in (420,493) if name=='install.sh' else item.get('mode')!=420) or (name in ('distribution-authority.json','distribution-authority.json.asc','install.sh.sig') and item.get('class')!='bootstrap'): raise ValueError('bootstrap artifact mismatch')
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
if (values.get('ID'),values.get('VERSION_ID')) not in (('debian','12'),('ubuntu','24.04'),('ubuntu','26.04')): raise SystemExit(1)
libc=ctypes.CDLL(None); libc.gnu_get_libc_version.restype=ctypes.c_char_p
parts=libc.gnu_get_libc_version().decode('ascii').split('.')
if len(parts)<2 or tuple(map(int,parts[:2]))<(2,36): raise SystemExit(1)
PY
if [ -z "$bundle" ]; then
    if [ -n "$version" ]; then
        printf 'Download release %s? It may be a test release rather than a stable release. [y/N] ' "$version" >&3
        explicit=yes
    else
        printf 'Find and download the latest approved stable release? [y/N] ' >&3
        explicit=no
    fi
    IFS= read -r choice <&3 || exit 3
    case "$choice" in y|Y|yes|YES|Yes) ;; *) exit 3 ;; esac
    work=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/p2kesup-release-XXXXXXXX") || exit 4
    keep_bundle=no
    trap 'if [ "$keep_bundle" = yes ]; then printf "Retained recovery bundle: %s\n" "$bundle" >&2; else rm -rf -- "$work"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
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
work=Path(sys.argv[1]); requested=sys.argv[2]
try:
    endpoint='https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases/'
    endpoint += 'tags/'+urllib.parse.quote(requested,safe='') if requested else 'latest'
    fetch(endpoint,1048576,work/'release.json')
    release=json.loads((work/'release.json').read_bytes(),object_pairs_hook=unique)
    tag=release.get('tag_name')
    if not isinstance(tag,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,254}',tag) or (requested and tag!=requested) or release.get('draft') is not False or (not requested and release.get('prerelease') is not False): raise ValueError('release identity or state mismatch')
    assets={}
    for a in release.get('assets',[]):
        name=a.get('name'); url=a.get('browser_download_url')
        if name in assets: raise ValueError('duplicate release asset')
        if isinstance(name,str) and isinstance(url,str): assets[name]=url
    for name in ('distribution-authority.json','distribution-authority.json.asc','release-authority.asc','distribution.json','distribution.json.sig','install.sh','install.sh.sig'):
        url=assets[name]; p=urllib.parse.urlsplit(url)
        if p.hostname!='github.com' or p.path!='/AndrewWestberg/pico2-kes-agent/releases/download/'+urllib.parse.quote(tag,safe='')+'/'+name: raise ValueError('untrusted release asset')
        fetch(url,1048576,work/name)
    shutil.copyfile(work/'release-authority.asc',work/'authority.asc')
    key=authenticate_authority(work)
    distribution_signature(work,key,'distribution.json','pico2-kes-agent-distribution-v1')
    distribution_signature(work,key,'install.sh','pico2-kes-agent-bootstrap-v1')
    manifest=json.loads((work/'distribution.json').read_bytes(),object_pairs_hook=unique)
    bind_bootstrap(manifest,work)
    identity=manifest.get('release',{})
    signed_tag=identity.get('tag')
    if manifest.get('schema_version')!=1 or manifest.get('purpose')!='pico2-kes-agent-distribution-v1' or manifest.get('qualification') not in ('qualified','candidate') or not isinstance(signed_tag,str) or identity.get('version')!=signed_tag or tag!=(('qualified-' if manifest['qualification']=='qualified' else '')+signed_tag) or (not requested and (manifest.get('qualification')!='qualified' or identity.get('channel')!='stable')): raise ValueError('signed release identity or admission status mismatch')
    entries={}
    for item in manifest.get('artifacts',[]):
        name=item.get('path'); size=item.get('size_bytes'); digest=item.get('sha256')
        if not isinstance(name,str) or len(name.encode())>240 or name.startswith('/') or '\\' in name or any(x in ('','.','..') for x in name.split('/')) or any(ord(c)<32 or ord(c)==127 for c in name) or name in entries or type(size)!=int or not 0<=size<=268435456 or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest) or item.get('mode') not in (420,493): raise ValueError('invalid artifact')
        entries[name]=item
    total=sum(x['size_bytes'] for x in entries.values())
    if not entries or len(entries)>256 or total>1073741824 or shutil.disk_usage(work).free < 2*total+2097152: raise ValueError('release bounds or free space')
    archive=assets['distribution.tar']; p=urllib.parse.urlsplit(archive)
    if p.hostname!='github.com' or p.path!='/AndrewWestberg/pico2-kes-agent/releases/download/'+urllib.parse.quote(tag,safe='')+'/distribution.tar': raise ValueError('untrusted archive origin')
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
    shutil.copyfile(work/'distribution.json.sig',output/'distribution.json.sig')
    print(output)
except BaseException:
    shutil.rmtree(work,ignore_errors=True)
    raise
PY
)" "$work" "$version"
    ) || { echo 'Release discovery or verification failed.' >&2; exit 4; }
else
    explicit=yes
fi
bundle=$(realpath -- "$bundle")
[ -d "$bundle" ] || { echo 'Bundle directory not found.' >&2; exit 4; }
/usr/bin/python3 -I -c "$verifier_code
$(cat <<'PY'
import hashlib, json, os, stat, subprocess, sys, tempfile
from pathlib import Path
bundle=Path(sys.argv[1]); explicit=sys.argv[2]=='yes'
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
    for path,name in ((bundle/'distribution.json','distribution.json'),(bundle/'distribution.json.sig','distribution.json.sig'),(bundle/'distribution-authority.json','distribution-authority.json'),(bundle/'distribution-authority.json.asc','distribution-authority.json.asc'),(bundle/'firmware/release-authority.asc','authority.asc'),(bundle/'install.sh','install.sh'),(bundle/'install.sh.sig','install.sh.sig')):
        (temp/name).write_bytes(read(path,1048576))
    key=authenticate_authority(temp)
    distribution_signature(temp,key,'distribution.json','pico2-kes-agent-distribution-v1')
    distribution_signature(temp,key,'install.sh','pico2-kes-agent-bootstrap-v1')
    manifest=json.loads((temp/'distribution.json').read_bytes(),object_pairs_hook=unique)
    bind_bootstrap(manifest,temp)
    if manifest.get('schema_version')!=1 or manifest.get('purpose')!='pico2-kes-agent-distribution-v1' or manifest.get('qualification') not in ('candidate','qualified') or (not explicit and manifest.get('qualification')!='qualified'): raise ValueError('release admission denied')
    entries=[x for x in manifest.get('artifacts',[]) if isinstance(x,dict) and x.get('path')=='bin/p2kesup']
    if len(entries)!=1: raise ValueError('ambiguous manager')
    binary=read(bundle/'bin/p2kesup',268435456)
    if len(binary)!=entries[0].get('size_bytes') or hashlib.sha256(binary).hexdigest()!=entries[0].get('sha256'): raise ValueError('manager digest mismatch')
PY
)" "$bundle" "$explicit" || { echo 'Bootstrap authentication failed before privilege handoff.' >&2; exit 4; }
echo 'The privileged verifier will authenticate and protect the selected manager before it runs.' >&2
root_code="$verifier_code
$(cat <<'PY'
import ctypes, hashlib, json, os, re, stat, subprocess, sys, tempfile
from pathlib import Path

bundle = Path(sys.argv[1]); explicit = sys.argv[2] == 'yes'; requested = sys.argv[3]; recovery = sys.argv[4] == 'yes'
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
    for source, name, limit in [(bundle/'distribution.json','distribution.json',1048576), (bundle/'distribution.json.sig','distribution.json.sig',1048576), (bundle/'distribution-authority.json','distribution-authority.json',1048576), (bundle/'distribution-authority.json.asc','distribution-authority.json.asc',1048576), (bundle/'firmware/release-authority.asc','authority.asc',1048576), (bundle/'install.sh','install.sh',1048576), (bundle/'install.sh.sig','install.sh.sig',1048576)]:
        (tmp/name).write_bytes(read(source, limit))
    key=authenticate_authority(tmp)
    distribution_signature(tmp,key,'distribution.json','pico2-kes-agent-distribution-v1')
    distribution_signature(tmp,key,'install.sh','pico2-kes-agent-bootstrap-v1')
    manifest=json.loads((tmp/'distribution.json').read_bytes(), object_pairs_hook=unique)
    bind_bootstrap(manifest,tmp)
    if manifest.get('schema_version') != 1 or manifest.get('purpose') != 'pico2-kes-agent-distribution-v1' or manifest.get('qualification') not in ('candidate','qualified'): fail('unsupported signed distribution')
    if not explicit and manifest['qualification'] != 'qualified': fail('candidate requires explicit --version or --bundle')
    release=manifest.get('release',{}); tag=release.get('tag')
    if requested and (not isinstance(tag,str) or release.get('version')!=tag or requested != (('qualified-' if manifest['qualification']=='qualified' else '')+tag)): fail('selected release identity changed')
    if not explicit and release.get('channel')!='stable': fail('default release is not stable')
    os_release={}
    for line in read(Path('/etc/os-release').resolve(strict=True),16384).decode().splitlines():
        if '=' in line:
            k,v=line.split('=',1); os_release[k]=v.strip('"')
    identity=(os_release.get('ID'),os_release.get('VERSION_ID'))
    if identity not in (('debian','12'),('ubuntu','24.04'),('ubuntu','26.04')): fail('unsupported operating system')
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
        if recovery or requirement.get('operation')!='install': continue
        for package in requirement.get('packages',[]):
            if (package.get('id'),package.get('version'))==identity:
                for name in package.get('names',[]):
                    if not isinstance(name,str) or not re.fullmatch('[a-z0-9][a-z0-9+.-]*',name): fail('invalid package name')
                    packages.add(name)
    if not recovery and not packages: fail('signed install prerequisites unavailable')
    missing=[]
    for package in sorted(packages):
        try: installed = bounded_command(['/usr/bin/dpkg-query','-W','-f=${Status}',package]) == b'install ok installed'
        except subprocess.CalledProcessError: installed = False
        if not installed: missing.append(package)
    if missing:
        apt_env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}
        with open('/dev/tty','r+') as tty:
            tty.write('Missing signed prerequisites: '+' '.join(missing)+'\nType REFRESH to approve apt-get update from trusted OS repositories: '); tty.flush()
            if tty.readline(257).strip()!='REFRESH': fail('package-index refresh declined')
            subprocess.run(['/usr/bin/apt-get','update'],env=apt_env,stdin=tty,stdout=tty,stderr=tty,check=True)
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
    for tool in ('/usr/bin/gpg','/usr/bin/gpgv','/usr/bin/openssl','/usr/bin/python3','/usr/bin/sudo','/usr/bin/readelf'):
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
if [ -n "$recovery_plan" ]; then recovery=yes; else recovery=no; fi
if [ "$(id -u)" -eq 0 ]; then
    manager=$(/usr/bin/python3 -I -c "$root_code" "$bundle" "$explicit" "$version" "$recovery") || { echo 'Authenticated bootstrap or prerequisites failed.' >&2; exit 4; }
else
    manager=$(/usr/bin/sudo -- /usr/bin/python3 -I -c "$root_code" "$bundle" "$explicit" "$version" "$recovery" <&3) || { echo 'Authenticated bootstrap or prerequisites failed.' >&2; exit 4; }
fi
if [ -n "${work:-}" ]; then keep_bundle=yes; fi
if [ -n "$recovery_plan" ]; then
    echo 'Bootstrap authenticated. Starting attended original-operation recovery.' >&2
    if [ "$(id -u)" -eq 0 ]; then
        "$manager" host-apply --plan "$recovery_plan" <&3 >&3 2>&3
    else
        /usr/bin/sudo -- "$manager" host-apply --plan "$recovery_plan" <&3 >&3 2>&3
    fi
else
    echo 'Bootstrap authenticated. Starting the reviewed installation.' >&2
    "$manager" install --bundle "$bundle" --role "$role" <&3 >&3 2>&3
fi
if [ -n "${work:-}" ]; then keep_bundle=no; fi
}
main "$@"
