"""OCI indexes and classic Docker image IDs are different objects."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

spec = importlib.util.spec_from_file_location('executor_build', Path(__file__).parents[2] / 'deploy/reliquary-workers/build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def archive(tmp_path, *, platform='amd64', revision=build.REVISION, copies=1):
    config = json.dumps({'architecture': platform, 'os': 'linux', 'config': {
        'Labels': {'org.opencontainers.image.revision': revision}}}).encode()
    config_id = hashlib.sha256(config).hexdigest()
    name = 'blobs/sha256/' + config_id
    path = tmp_path / 'image.tar'
    with tarfile.open(path, 'w') as tar:
        for key, data in {
            name: config,
            'manifest.json': json.dumps([{'Config': name, 'Layers': []}] * copies).encode(),
            'index.json': json.dumps({'manifests': [{'digest': 'sha256:' + 'f' * 64}]}).encode(),
        }.items():
            member = tarfile.TarInfo(key)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return path, 'sha256:' + config_id


def test_portable_id_is_loaded_config_not_builder_index(tmp_path):
    path, expected = archive(tmp_path)
    assert build.portable_image_id(path) == expected
    assert expected != 'sha256:' + 'f' * 64


@pytest.mark.parametrize('kwargs', [{'platform': 'arm64'}, {'revision': 'unreviewed'}, {'copies': 2}])
def test_wrong_or_ambiguous_image_refused(tmp_path, kwargs):
    path, _ = archive(tmp_path, **kwargs)
    with pytest.raises(ValueError):
        build.portable_image_id(path)
