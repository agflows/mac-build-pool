"""Owner acceptance only: generate a Flutter plugin fixture inside a fresh guest.

Stdout is a bounded source archive to be ingested as opaque bytes by the broker.
No project code runs on the host. Never use this staging guest as a base image.
"""
import io,json,os,subprocess,sys,tarfile
from pathlib import Path
sys.path.insert(0,'/Library/ios-worker')
from execution_policy import require_worker_execution,require_protected_file
from config import load_worker_config
from workspace import toolchain_paths,copy_flutter_sdk,workspace_env
require_worker_execution()
config=Path('/Library/ios-worker/worker.json');require_protected_file(config)
cfg=load_worker_config(config)
project=cfg.workspace_root/'flutter-fixture-seed'
project.mkdir(mode=0o700,exist_ok=False)
tools=toolchain_paths(cfg,'flutter-ios')
copy_flutter_sdk(project,tools['flutter_sdk'])
env=workspace_env(project,cfg,tools=tools)
flutter=str(project/'.worker/flutter/bin/flutter')
def run(argv):
    subprocess.run(argv,cwd=project,env=env,stdout=sys.stderr,stderr=sys.stderr,timeout=1200,check=True)
run([flutter,'create','--platforms','ios','--org','org.agflows','--project-name','flutter_probe','--empty',str(project)])
pubspec=project/'pubspec.yaml'
pubspec.write_text(pubspec.read_text().replace('dependencies:\n','dependencies:\n  shared_preferences: 2.5.6\n',1))
(project/'lib/main.dart').write_text('''import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final preferences = await SharedPreferences.getInstance();
  await preferences.setString('fixture', 'local plugin works');
  runApp(MaterialApp(home: Scaffold(body: Center(child: Column(
    mainAxisSize: MainAxisSize.min,
    children: [const Text('Flutter isolated build'), Text(preferences.getString('fixture')!)]
  )))));
}
''')
run([flutter,'pub','get'])
run([flutter,'analyze'])
archive=io.BytesIO();total=0
ignored={'.worker','.dart_tool','build','.git','.idea','Pods','.symlinks','ephemeral'}
with tarfile.open(fileobj=archive,mode='w:gz') as tar:
    for path in sorted(project.rglob('*')):
        relative=path.relative_to(project)
        if ignored.intersection(relative.parts) or path.name in {'Generated.xcconfig','flutter_export_environment.sh'}:continue
        if path.is_symlink():raise RuntimeError('Fixture contains an unexpected link')
        if path.is_file():
            total+=path.stat().st_size
            if total>64*1024*1024:raise RuntimeError('Fixture source exceeds bound')
            tar.add(path,arcname=str(relative),recursive=False)
sys.stdout.buffer.write(archive.getvalue())
