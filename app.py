import os
import subprocess
import tempfile
import zipfile
import plistlib
import requests
import logging
import time
import shutil
from flask import Flask, request, jsonify, send_file, abort

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB limit

ZSIGN_PATH = './zsign'  # calea către zsign

if os.path.exists(ZSIGN_PATH):
    os.chmod(ZSIGN_PATH, 0o755)

def extract_bundle_and_name(ipa_path):
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            zip_ref.extractall(tmpdir)
        payload = os.path.join(tmpdir, 'Payload')
        apps = [d for d in os.listdir(payload) if d.endswith('.app')]
        if not apps:
            raise Exception("No .app folder found in Payload")
        app_path = os.path.join(payload, apps[0])
        plist_path = os.path.join(app_path, 'Info.plist')
        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)
        bundle_id = plist.get('CFBundleIdentifier')
        app_name = plist.get('CFBundleDisplayName') or plist.get('CFBundleName') or "UnknownApp"
        return bundle_id, app_name

def generate_manifest(bundle_id, app_name, ipa_url):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>{ipa_url}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>{bundle_id}</string>
        <key>bundle-version</key>
        <string>1.0</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>{app_name}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>"""

def upload_to_transfersh(file_path):
    filename = os.path.basename(file_path)
    url = f'https://transfer.sh/{filename}'
    try:
        with open(file_path, 'rb') as f:
            r = requests.put(url, data=f)
        r.raise_for_status()
        return r.text.strip(), None
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return None, str(e)

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join('/tmp', filename)
    if not os.path.exists(path):
        abort(404)
    if not filename.endswith('.ipa'):
        abort(400)
    return send_file(path, as_attachment=True)

@app.route('/sign', methods=['POST'])
def sign_ipa():
    ipa = request.files.get('ipa')
    p12 = request.files.get('p12')
    provision = request.files.get('provision')
    password = request.form.get('password')

    if not ipa or not p12 or not provision or not password:
        return jsonify({'error': 'Missing IPA, P12, provisioning profile or password'}), 400

    if not ipa.filename.endswith('.ipa'):
        return jsonify({'error': 'IPA file must have .ipa extension'}), 400
    if not p12.filename.endswith('.p12'):
        return jsonify({'error': 'Certificate must have .p12 extension'}), 400
    if not provision.filename.endswith('.mobileprovision'):
        return jsonify({'error': 'Provisioning profile must have .mobileprovision extension'}), 400

    with tempfile.TemporaryDirectory() as tmpdir:
        ipa_path = os.path.join(tmpdir, 'input.ipa')
        p12_path = os.path.join(tmpdir, 'cert.p12')
        provision_path = os.path.join(tmpdir, 'profile.mobileprovision')
        output_path = os.path.join(tmpdir, 'signed.ipa')
        manifest_path = os.path.join(tmpdir, 'manifest.plist')

        ipa.save(ipa_path)
        p12.save(p12_path)
        provision.save(provision_path)

        try:
            bundle_id, app_name = extract_bundle_and_name(ipa_path)
        except Exception as e:
            return jsonify({'error': 'Failed extracting bundle info', 'details': str(e)}), 500

        cmd = [ZSIGN_PATH, '-k', p12_path, '-p', password, '-m', provision_path, '-o', output_path, ipa_path]
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Signing failed', 'details': e.output}), 500

        signed_filename = f"signed_{bundle_id}_{int(time.time())}.ipa"
        permanent_path = os.path.join('/tmp', signed_filename)
        shutil.copy2(output_path, permanent_path)

        ipa_url, err = upload_to_transfersh(output_path)
        if err:
            return jsonify({'error': 'IPA upload failed', 'details': err}), 500

        manifest_content = generate_manifest(bundle_id, app_name, ipa_url)
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write(manifest_content)

        manifest_url, manifest_err = upload_to_transfersh(manifest_path)
        if manifest_err:
            return jsonify({'error': 'Manifest upload failed', 'details': manifest_err}), 500

        itms_url = f"itms-services://?action=download-manifest&url={manifest_url}"

        return jsonify({
            'success': True,
            'itms_services_url': itms_url,
            'direct_download': f'/download/{signed_filename}',
            'app_info': {
                'name': app_name,
                'bundle_id': bundle_id
            }
        })

if __name__ == '__main__':
    if os.path.exists(ZSIGN_PATH):
        os.chmod(ZSIGN_PATH, 0o755)
    app.run(host='0.0.0.0', port=5000, debug=True)
