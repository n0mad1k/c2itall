#!/usr/bin/env python3
"""Synthetic lab datasets for the LUDUS range: finance ledgers, an employee
database, fake credential documents, backup bulk and one canary document.
Runs on the LUDUS host; `lab-datasets.service` serves the output over HTTP.
"""
import argparse
import csv
import hashlib
import json
import os
import random
import shutil
import sqlite3
import tarfile
import time
import uuid
import zipfile

SETS = {'small': 10 * 1024 * 1024, 'medium': 250 * 1024 * 1024, 'large': 1200 * 1024 * 1024}

DOCX_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>')
DOCX_PACKAGE_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/></Relationships>')
XLSX_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    '</Types>')
XLSX_PACKAGE_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="xl/workbook.xml"/></Relationships>')
XLSX_WORKBOOK = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>')


def _docx_document_rels(canary_url):
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    if canary_url:
        # Classic canary token: an external relationship Word resolves on open.
        parts.append(
            '<Relationship Id="rIdCanary" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
            'Target="{0}" TargetMode="External"/>'.format(canary_url))
    parts.append('</Relationships>')
    return ''.join(parts)


def write_docx(path, body_text, canary_url=None):
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                '<w:body><w:p><w:r><w:t>{0}</w:t></w:r></w:p></w:body></w:document>').format(body_text)
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', DOCX_CONTENT_TYPES)
        archive.writestr('_rels/.rels', DOCX_PACKAGE_RELS)
        archive.writestr('word/document.xml', document)
        archive.writestr('word/_rels/document.xml.rels', _docx_document_rels(canary_url))


def write_xlsx(path, rows):
    sheet_rows = []
    for r, row in enumerate(rows, 1):
        cells = ''.join('<c t="inlineStr"><is><t>{0}</t></is></c>'.format(value) for value in row)
        sheet_rows.append('<row r="{0}">{1}</row>'.format(r, cells))
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             '<sheetData>{0}</sheetData></worksheet>').format(''.join(sheet_rows))
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', XLSX_CONTENT_TYPES)
        archive.writestr('_rels/.rels', XLSX_PACKAGE_RELS)
        archive.writestr('xl/workbook.xml', XLSX_WORKBOOK)
        archive.writestr('xl/worksheets/sheet1.xml', sheet)


def write_ledger_csv(path, rows):
    with open(path, 'w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['date', 'account', 'description', 'amount'])
        for i in range(rows):
            writer.writerow([time.strftime('%Y-%m-%d'), 'ACC-{0:05d}'.format(i % 500),
                              'txn {0}'.format(i), '{0:.2f}'.format(random.uniform(-5000, 5000))])


def write_employees_db(path, count):
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, department TEXT, '
                 'email TEXT, salary INTEGER)')
    departments = ['Finance', 'Payroll', 'Executives', 'IT Operations', 'VMware Administrators']
    conn.executemany(
        'INSERT INTO employees (name, department, email, salary) VALUES (?, ?, ?, ?)',
        [('Employee {0}'.format(i), random.choice(departments), 'employee{0}@lab.internal'.format(i),
          random.randint(45000, 180000)) for i in range(count)])
    conn.commit()
    conn.close()


def write_random_file(path, size):
    chunk = os.urandom(1024 * 1024)
    with open(path, 'wb') as stream:
        remaining = size
        while remaining > 0:
            n = min(len(chunk), remaining)
            stream.write(chunk[:n])
            remaining -= n


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def generate_set(name, scale, out_dir, canary_url):
    # Each set lives in its own subdirectory so filenames don't collide when
    # --all runs every set into the same output directory.
    set_dir = os.path.join(out_dir, name)
    os.makedirs(set_dir, exist_ok=True)
    target = int(SETS[name] * scale)
    files = []

    def record(path):
        files.append({'path': os.path.relpath(path, out_dir), 'size': os.path.getsize(path),
                      'sha256': _sha256(path)})

    ledger_path = os.path.join(set_dir, 'finance_ledger.csv')
    write_ledger_csv(ledger_path, max(20, int(2000 * scale)))
    record(ledger_path)

    employees_path = os.path.join(set_dir, 'employees.sqlite3')
    write_employees_db(employees_path, max(10, int(500 * scale)))
    record(employees_path)

    backup_path = os.path.join(set_dir, 'employees.sqlite3.bak')
    shutil.copyfile(employees_path, backup_path)
    record(backup_path)

    creds_xlsx_path = os.path.join(set_dir, 'credentials.xlsx')
    write_xlsx(creds_xlsx_path, [['service', 'username', 'password'],
                                 ['vpn', 'svc-vpn', 'ChangeMe123!'],
                                 ['backup', 'backupop', 'Backup2024!']])
    record(creds_xlsx_path)

    creds_docx_path = os.path.join(set_dir, 'credentials.docx')
    write_docx(creds_docx_path, 'Shared credentials: see the IT Operations share.')
    record(creds_docx_path)

    canary_token = str(uuid.uuid4())
    canary_path = os.path.join(set_dir, 'CANARY-{0}.docx'.format(canary_token))
    write_docx(canary_path, 'Quarterly financial review draft.', canary_url=canary_url)
    record(canary_path)

    quarterly_path = os.path.join(set_dir, 'quarterly.tar.gz')
    with tarfile.open(quarterly_path, 'w:gz') as archive:
        archive.add(ledger_path, arcname='finance_ledger.csv')
    record(quarterly_path)

    remaining = max(0, target - sum(entry['size'] for entry in files))
    index = 1
    while remaining > 0:
        size = min(max(1024 * 1024, remaining // 3), remaining)
        vbk_path = os.path.join(set_dir, 'vm-{0:02d}.vbk'.format(index))
        write_random_file(vbk_path, size)
        record(vbk_path)
        remaining -= size
        index += 1

    manifest = {'set': name, 'generated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'canary_token': canary_token, 'total_bytes': sum(entry['size'] for entry in files),
                'files': files}
    manifest_path = os.path.join(out_dir, 'manifest-{0}.json'.format(name))
    with open(manifest_path, 'w') as stream:
        json.dump(manifest, stream, indent=2)
    return manifest_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scale', type=float, default=1.0, help='size multiplier (tests use 0.02)')
    parser.add_argument('--all', action='store_true', help='generate every set')
    parser.add_argument('--set', choices=sorted(SETS), action='append', help='generate one set (repeatable)')
    parser.add_argument('--out', default='/srv/lab-datasets')
    parser.add_argument('--canary-url', help='external relationship target for the canary document')
    args = parser.parse_args()
    names = sorted(SETS) if args.all or not args.set else args.set
    for name in names:
        print(generate_set(name, args.scale, args.out, args.canary_url))


if __name__ == '__main__':
    main()
