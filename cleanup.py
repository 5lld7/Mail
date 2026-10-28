"""Preview and remove only old, regular files in fixed cache/log directories."""
import os
import stat
import time
from pathlib import Path

POLICIES = {
    'system': ('لوجات النظام المؤرشفة', '/var/log', 'logs'),
    'web': ('لوجات OpenLiteSpeed المؤرشفة', '/usr/local/lsws/logs', 'logs'),
    'apt': ('حزم APT المحفوظة في الكاش', '/var/cache/apt/archives', 'apt'),
}
MIN_AGE = 14 * 86400


def preview_all():
    files = []
    available = False
    for category, (_, path, _) in POLICIES.items():
        result = preview(category)
        available = available or result['available']
        files.extend(dict(item, category=category, directory=path) for item in result['files'])
    return {'label': 'تنظيف شامل للوجات المؤرشفة وكاش الحزم', 'files': files,
            'bytes': sum(item['bytes'] for item in files), 'available': available}


def execute_all(files):
    totals = {'deleted': 0, 'skipped': 0, 'bytes': 0}
    for category in POLICIES:
        selected = [item for item in files if item['category'] == category]
        if not selected:
            continue
        try:
            result = execute(category, selected)
        except (OSError, ValueError):
            result = {'deleted': 0, 'skipped': len(selected), 'bytes': 0}
        for key in totals:
            totals[key] += result[key]
    return totals


def directory(path):
    # No symlink components, including the directory itself.
    if str(Path(path).resolve()) != path:
        raise ValueError('مسار التنظيف يحتوي على رابط رمزي؛ تم رفضه.')
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def eligible(name, info, kind):
    suffix = name.endswith('.deb') if kind == 'apt' else (
        name.endswith(('.gz', '.xz', '.bz2')) or name.rsplit('.', 1)[-1].isdigit())
    return (suffix and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_mtime < time.time() - MIN_AGE)


def preview(category):
    label, path, kind = POLICIES[category]
    files = []
    try:
        fd = directory(path)
    except FileNotFoundError:
        return {'label': label, 'files': [], 'bytes': 0, 'available': False}
    try:
        for name in sorted(os.listdir(fd)):
            if len(files) >= 1000:
                break
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if eligible(name, info, kind):
                files.append({'name': name, 'bytes': info.st_size, 'inode': info.st_ino,
                              'mtime': info.st_mtime_ns, 'device': info.st_dev})
    finally:
        os.close(fd)
    return {'label': label, 'files': files, 'bytes': sum(f['bytes'] for f in files),
            'available': True}


def execute(category, files):
    _, path, kind = POLICIES[category]
    fd = directory(path)
    deleted, skipped, freed = 0, 0, 0
    try:
        for item in files:
            name = item['name']
            if '/' in name or name in ('.', '..'):
                raise ValueError('اسم ملف غير صالح')
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (not eligible(name, info, kind) or
                    (info.st_ino, info.st_mtime_ns, info.st_size, info.st_dev) !=
                    (item['inode'], item['mtime'], item['bytes'], item['device'])):
                    skipped += 1
                    continue
                os.unlink(name, dir_fd=fd)
                deleted += 1
                freed += item['bytes']
            except OSError:
                skipped += 1
    finally:
        os.close(fd)
    return {'deleted': deleted, 'skipped': skipped, 'bytes': freed}
