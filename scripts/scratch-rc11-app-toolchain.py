#!/usr/bin/env python3
"""Read toolchain evidence from the two exact App manifests without starting them."""
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import uuid


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=120).stdout


def source_paths(sbom):
    for component in sbom['components']:
        for prop in component.get('properties', []):
            if not re.fullmatch(r'syft:location:[0-9]+:path', prop['name']):
                continue
            name, path = component['name'], prop['value']
            if name == 'stdlib' and (path == '/usr/bin/caddy' or path.endswith('/bin/esbuild')):
                yield (name, path, component['version'])
            if name == 'tar' and '/corepack/v1/pnpm/' in path and path.endswith('/tar/package.json'):
                yield (name, path, component['version'])


def inspect(platform, image):
    if not re.fullmatch(r'ghcr\.io/lingkaix/openkit-app@sha256:[0-9a-f]{64}', image):
        raise ValueError('Exact App manifest reference required')
    fields = '{{.Id}} {{.Os}}/{{.Architecture}}'
    image_id, actual = run('docker', 'image', 'inspect', '--platform', platform, '--format', fields, image).split()
    if actual != platform or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('App image identity differs')
    container = run(
        'docker', 'create', '--name', f'openkit-rc11-toolchain-{uuid.uuid4().hex}',
        '--pull=never', '--platform', platform, '--network=none', '--entrypoint', '/bin/true', image_id,
    ).strip()
    if not re.fullmatch(r'[0-9a-f]{64}', container):
        raise ValueError('Stopped container identity was not confirmed')
    try:
        with tempfile.TemporaryDirectory(prefix='openkit-rc11-toolchain-') as temporary:
            work = Path(temporary)
            sbom_path = work / 'sbom.json'
            run('docker', 'cp', f'{container}:/app/security/sbom.cdx.json', str(sbom_path))
            evidence = []
            for index, (name, path, expected) in enumerate(sorted(set(source_paths(json.loads(sbom_path.read_bytes()))))):
                if not path.startswith('/') or '..' in PurePosixPath(path).parts or str(PurePosixPath(path)) != path:
                    raise ValueError('Invalid component file path')
                extracted = work / f'component-{index}'
                run('docker', 'cp', '-L', f'{container}:{path}', str(extracted))
                if name == 'stdlib':
                    header = run('go', 'version', '-m', str(extracted)).splitlines()[0]
                    version = header.split()[-1]
                else:
                    package = json.loads(extracted.read_bytes())
                    if package['name'] != 'tar':
                        raise ValueError('Corepack package identity differs')
                    version = package['version']
                if version != expected:
                    raise ValueError(f'SBOM and component bytes disagree for {path}')
                evidence.append({'component': name, 'path': path, 'version': version})
            if not any(item['path'] == '/usr/bin/caddy' for item in evidence):
                raise ValueError('Missing Caddy Go version')
            if not any(item['component'] == 'tar' for item in evidence):
                raise ValueError('Missing Corepack pnpm tar version')
            return {'platform': platform, 'manifest': image, 'imageId': image_id, 'components': evidence}
    finally:
        run('docker', 'rm', '--volumes', container)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Pass the already-pulled amd64 and arm64 App manifest references')
    print(json.dumps([
        inspect('linux/amd64', sys.argv[1]),
        inspect('linux/arm64', sys.argv[2]),
    ], indent=2))
