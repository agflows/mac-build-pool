"""Broker client for the protected, lease-scoped Tart service."""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import pwd
import stat
import threading
import hashlib

from containment import MAX_ARTIFACT_BYTES
from execution_policy import require_protected_file
from policy import check_device, require_id, require_under, PolicyError
from runner import WorkerFailure
from vm_transport import rpc

CONFIG = Path('/Library/ios-worker/vm.json')
PROOF = Path('/Library/ios-worker/vm-validated.json')


class TartRunner:
    execution_mode = 'isolated-only'
    unavailable_code = 'isolation_required'
    vm_backend = True

    def __init__(self, allowlist, denylist, worker, *, validation_mode=False):
        self.allowlist,self.denylist,self.worker=allowlist,denylist,worker
        self.archives={}
        self.staged=set()
        self.lease=None
        self.lock=threading.RLock()
        self.validation_mode=validation_mode

    def verified(self):
        try:
            require_protected_file(PROOF)
            proof=json.loads(PROOF.read_text())
            from containment import CODE_FILES
            root=Path('/Library/ios-worker')
            config = CONFIG.read_bytes()
            digest=hashlib.sha256()
            for name in sorted(CODE_FILES):
                digest.update(name.encode()+b'\0'+(root/name).read_bytes())
            return (proof.get('codeSHA256')==digest.hexdigest()
                    and proof.get('vmConfigSHA256')==hashlib.sha256(config).hexdigest()
                    and proof.get('appBuildPassed') is True
                    and proof.get('securityNegativesPassed') is True and proof.get('leaseExpiryPassed') is True
                    and (not json.loads(config).get('watch_devices') or proof.get('watchBuildPassed') is True))
        except (OSError,ValueError,PolicyError):
            return False

    def _call(self, request, timeout=30):
        require_protected_file(CONFIG)
        cfg=json.loads(CONFIG.read_text())
        path=Path(cfg['socket'])
        if path != Path('/Library/ios-worker/control/vm.sock'):
            raise PolicyError('unsafe_executor','VM control socket path is fixed')
        owner=pwd.getpwnam('iosvm').pw_uid
        info=path.lstat()
        parent=path.parent.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=owner or info.st_mode & 0o007
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=owner or parent.st_mode & 0o022):
            raise PolicyError('unsafe_executor','VM control socket is not protected')
        result=rpc(path,request,timeout=timeout)
        if result.get('ok') is not True:
            raise WorkerFailure(str(result.get('message') or result.get('error') or 'VM operation failed'),result.get('exitCode'))
        return result

    def installed(self):
        try:
            result=self._call({'op':'capabilities'},timeout=5)
            return (result.get('version')==1 and result.get('backend')=='tart'
                    and result.get('network')=='disconnected-ethernet+allowlisted-connect'
                    and (self.validation_mode or self.verified()))
        except (OSError,ValueError,PolicyError,WorkerFailure):
            return False

    def lease_acquire(self, lease_id, ttl):
        with self.lock:
            result=self._call({'op':'reserve','lease_id':lease_id,'ttl':ttl})
            self.lease=lease_id
            self.staged.clear()
            return result

    def lease_renew(self, lease_id, ttl):
        return self._call({'op':'renew','lease_id':lease_id,'ttl':ttl})

    def lease_release(self, lease_id):
        with self.lock:
            result=self._call({'op':'release','lease_id':lease_id},timeout=90)
            if self.lease==lease_id:
                self.lease=None
            return result

    def is_booted(self, device_id):
        check_device(device_id,self.allowlist,self.denylist)
        state=self._call({'op':'status'})
        if state.get('state')!='active' or not self.lease:
            return False
        # The controller gives CoreSimulator up to 120 seconds to answer.
        result = self._call({'op': 'booted', 'lease_id': self.lease, 'device_id': device_id}, timeout=135)
        return result.get('booted') is True

    def vm_started(self):
        return self._call({'op':'status'}).get('state')=='active'

    def lease_alive(self,lease_id):
        return self.lease==lease_id and self._call({'op':'status'}).get('state') in {'reserved','starting','active'}

    def shutdown(self, device_id):
        check_device(device_id,self.allowlist,self.denylist)
        state=self._call({'op':'status'})
        if state.get('state')=='active' and self.lease:
            self._call({'op':'shutdown','lease_id':self.lease,'device_id':device_id},timeout=120)

    def run(self, job):
        if not self.validation_mode and not self.verified():
            raise PolicyError('isolation_required', 'The installed VM configuration requires acceptance.')
        if job.device_id:
            check_device(job.device_id,self.allowlist,self.denylist)
        if job.kind=='ingest':
            revision=require_id(job.revision_id,'revision')
            path=require_under(Path(job.archive),self.worker.spool_root)
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size>self.worker.max_upload_bytes:
                raise PolicyError('invalid_archive','invalid staged source')
            self.archives[revision]=path
            return {'ok':True,'log':'Source staged as opaque bytes; extraction waits for the leased VM.'}
        if not self.lease or job.lease_id != self.lease:
            raise PolicyError('lease_required','job does not own the current VM lease')
        request={'op':job.kind,'job_id':job.id,'lease_id':job.lease_id,
                 **{key:getattr(job,key) for key in ('revision_id','session_id','device_id','scheme','recipe',
                   'public_env','configuration','for_testing','artifact_id','approved')}}
        if job.revision_id and job.revision_id not in self.staged and job.kind in {'prepare','build','launch','uitest'}:
            source=self.archives.get(job.revision_id)
            if source is None:
                raise PolicyError('unknown_revision','staged source is unavailable; upload it again')
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size>self.worker.max_upload_bytes:
                    raise PolicyError('invalid_archive','invalid staged source')
                raw=stream.read(self.worker.max_upload_bytes+1)
            if len(raw)>self.worker.max_upload_bytes:
                raise PolicyError('invalid_archive','source exceeds transfer limit')
            request['source_base64']=base64.b64encode(raw).decode()
        result=self._call(request,timeout=3000)
        # Guest-supplied paths never authorize reads of physical-host files.
        result.pop('artifact_path',None)
        result.pop('artifact_id',None)
        if job.revision_id and job.kind in {'prepare','build','launch','uitest'}:
            self.staged.add(job.revision_id)
        if job.kind=='reset' and job.revision_id:
            self.staged.discard(job.revision_id)
        artifact=result.pop('artifact_base64',None)
        if artifact is not None:
            artifact_id=require_id(job.artifact_id or job.id,'artifact')
            raw=base64.b64decode(artifact,validate=True)
            if len(raw)>MAX_ARTIFACT_BYTES:
                raise PolicyError('storage_limit','artifact exceeds transfer limit')
            suffix='.png' if job.kind=='screenshot' else '.log'
            if suffix=='.png' and not raw.startswith(b'\x89PNG\r\n\x1a\n'):
                raise PolicyError('invalid_artifact','screenshot must contain PNG bytes')
            path=self.worker.artifact_root/(artifact_id+suffix)
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw)
            result.update(artifact_id=artifact_id,artifact_path=str(path))
        return result
