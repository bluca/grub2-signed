#!/usr/bin/python3

import sys
sys.path.append(sys.argv[1] + "/lib/python")

import os, os.path, shutil, subprocess, tempfile
import deb822, codecs, hashlib, io, lzma, re, struct, urllib.parse, urllib.request
import gc

class ArchiveMetadataError(Exception):
    pass

class MissingPackageError(Exception):
    pass

_release_data = {}

def get_release_data(mirror, suite):
    if (mirror, suite) not in _release_data:
        # I would prefer to use InRelease here to avoid a possible
        # mismatch but inline-signed files can include unsigned text
        # that we might mistakenly trust.
        url = urllib.parse.urljoin(mirror, 'dists/%s/Release' % suite)
        print('I: Fetching %s' % url)
        with urllib.request.urlopen(url) as req:
            release_raw = req.read()
        url += '.gpg'
        print('I: Fetching %s' % url)
        with urllib.request.urlopen(url) as req:
            release_sig_raw = req.read()

        # Validate against keyring.  deb822.Release doesn't support
        # signatures (inline or detached) for some reason so call gpgv
        # directly.
        with tempfile.NamedTemporaryFile() as release_file, \
             tempfile.NamedTemporaryFile() as release_sig_file:
            release_file.write(release_raw)
            release_file.flush()
            release_sig_file.write(release_sig_raw)
            release_sig_file.flush()
            output = subprocess.check_output(
                ['gpgv', '--status-fd', '1',
                 '--keyring', '/usr/share/keyrings/debian-archive-keyring.gpg',
                 '--ignore-time-conflict', release_sig_file.name,
                 release_file.name])
            if not re.search(r'^\[GNUPG:\]\s+VALIDSIG\s', codecs.decode(output),
                             re.MULTILINE):
                os.write(2, output) # bytes not str!
                raise ArchiveMetadataError('gpgv rejected %s' % url)

        release_stream = io.TextIOWrapper(io.BytesIO(release_raw), 'utf-8')

        # Make a dictionary of per-file data
        _release_data[(mirror, suite)] = data = {}
        for file_data in deb822.Release(release_stream)['SHA256']:
            data[file_data['name']] = file_data

    return _release_data[(mirror, suite)]

_packages_data = {}

def get_packages_data(mirror, suite, arch):
    if (mirror, suite, arch) not in _packages_data:
        release_data = get_release_data(mirror, suite)

        path = 'main/binary-%s/Packages.xz' % arch
        file_data = release_data[path]
        url = urllib.parse.urljoin(mirror, 'dists/%s/%s' % (suite, path))
        print('I: Fetching %s' % url)
        with urllib.request.urlopen(url) as req:
            packages_raw = req.read()

        # Validate against Release file
        if len(packages_raw) != int(file_data['size']):
            raise ArchiveMetadataError('%s has wrong size' % url)
        h = hashlib.sha256()
        h.update(packages_raw)
        if h.digest() != bytes.fromhex(file_data['sha256']):
            raise ArchiveMetadataError('%s has wrong checksum' % url)

        packages_stream = io.TextIOWrapper(
            io.BytesIO(lzma.decompress(packages_raw)), 'utf-8')

        # Make a dictionary of per-package data
        _packages_data[(mirror, suite, arch)] = data = {}
        for package_data in deb822.Packages.iter_paragraphs(packages_stream):
            name = package_data['Package']
            # Filter so the heap doesn't become huge
            if name.startswith('linux-image-'):
                data[name] = package_data

    return _packages_data[(mirror, suite, arch)]

def get_package(mirror, suite, name, version, arch):
    packages_dir = 'debian/localpackages/'
    package_file = '%s/%s_%s_%s.deb' % (packages_dir, name, version, arch)
    unpack_dir = '%s/%s_%s_%s' % (packages_dir, name, version, arch)

    os.makedirs(packages_dir, exist_ok=True)

    if not os.path.isfile(package_file):
        packages_data = get_packages_data(mirror, suite, arch)
        if name not in packages_data:
            raise MissingPackageError('package %s is not available' % name)
        package_data = packages_data[name]
        if package_data['Version'] != version:
            raise MissingPackageError(
                'package %s version %s is not available; only version %s' %
                (name, version, package_data['Version']))
        url = urllib.parse.urljoin(mirror, package_data['Filename'])
        print('I: Fetching %s' % url)
        with urllib.request.urlopen(url) as req:
            package = req.read()

        # Validate against Packages file
        if len(package) != int(package_data['Size']):
            raise ArchiveMetadataError('%s has wrong size' % url)
        h = hashlib.sha256()
        h.update(package)
        if h.digest() != bytes.fromhex(package_data['SHA256']):
            raise ArchiveMetadataError('%s has wrong checksum' % url)

        with open(package_file, 'wb') as f:
            f.write(package)

    if not os.path.isdir(unpack_dir):
        # Unpack to a temporary directory before moving into place, so we
        # don't cache a half-unpacked package
        unpack_temp_dir = unpack_dir + '.temp'
        if os.path.isdir(unpack_temp_dir):
            shutil.rmtree(unpack_temp_dir)
        os.makedirs(unpack_temp_dir)
        subprocess.check_call(['dpkg-deb', '-x', package_file, unpack_temp_dir])
        os.rename(unpack_temp_dir, unpack_dir)

    return unpack_dir

def sign_image_efi(image_name, signature_name, privkey_name, cert_name):
    print('I: Signing image %s' % image_name)
    print('I: Storing detached signature as %s' % signature_name)
    os.makedirs(os.path.dirname(signature_name), exist_ok=True)
    subprocess.check_call(['sbsign', '--key', privkey_name, '--cert', cert_name,
                           '--detached', '--output', signature_name, image_name])
    # Work around bug #819987
    if not os.path.isfile(signature_name):
        raise Exception('sbsign failed')

def sign_image_efi_pesign(image_name, signature_name, nss_dir, cert_name,
                          nss_token=""):
    print('I: Signing image %s' % image_name)
    print('I: Storing detached signature as %s' % signature_name)
    os.makedirs(os.path.dirname(signature_name), exist_ok=True)
    subprocess.check_call(['pesign', '-s', '-n', nss_dir, '-c', cert_name,
                           '--export-signature', signature_name,
                           '-i', image_name] +
                           ([] if len(nss_token) == 0 else ['-t', nss_token]))
    # Work around bug #819987
    if not os.path.isfile(signature_name):
        raise Exception('pesign failed')

def sign(grubversion_str, arch, package_name, image_privkey_name,
         image_cert_name, mirror_url, suite, signer='sbsign',
         nss_dir=None, nss_token=""):
    signature_dir = 'debian/signatures'
    if os.path.isdir(signature_dir):
        shutil.rmtree(signature_dir)

    try:
        package_dir = get_package(mirror_url, suite,
                              package_name, grubversion_str, arch)
    except MissingPackageError:
        package_dir = get_package(
            'http://incoming.debian.org/debian-buildd/',
            'buildd-' + suite,
            package_name, imageversion_str, arch)

    signature_dir = os.path.join('debian/signatures', package_name)
    os.makedirs(signature_dir)

    for walk_dir, subdir_names, file_names in os.walk(package_dir):
        for rel_name in file_names:
            rel_dir = os.path.relpath(walk_dir, package_dir)
            if rel_name.endswith('.efi'):
                if signer == 'sbsign':
                    sign_image_efi('%s/%s' % (walk_dir, rel_name),
                                   '%s/%s/%s.sig' % (signature_dir, rel_dir, rel_name),
                                   image_privkey_name, image_cert_name)
                elif signer == 'pesign':
                    sign_image_efi_pesign('%s/%s' % (walk_dir, rel_name),
                                   '%s/%s/%s.sig' % (signature_dir, rel_dir, rel_name),
                                   nss_dir, image_cert_name, nss_token)
                else:
                    raise Exception('unknown signer')

    print('Signatures should be committed: git add debian/signatures && git commit')

if __name__ == '__main__':
    sign(*sys.argv[1:])
