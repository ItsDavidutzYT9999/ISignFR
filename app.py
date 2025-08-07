import os
import subprocess
import tempfile
import zipfile
import plistlib
import requests
import logging
import time
import shutil
from flask import Flask, request, jsonify, render_template, send_file, abort

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB limit
app.config['UPLOAD_FOLDER'] = '/tmp'

ZSIGN_PATH = './zsign'  # Calea către executabilul zsign

if os.path.exists(ZSIGN_PATH):
    os.chmod(ZSIGN_PATH, 0o755)

def extract_bundle_and_name(ipa_path):
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            zip_ref.extractall(tmpdir)

        payload_path = os.path.join(tmpdir, 'Payload')
        apps = [d for d in os.listdir(payload_path) if d.endswith('.app')]
        if not apps:
            raise Exception("No .app folder found in Payload")

        app_path = os.path.join(payload_path, apps[0])
        info_plist_path = os.path.join(app_path, 'Info.plist')

        with open(info_plist_path, 'rb') as f:
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

def upload_to_gofile(file_path):
    try:
        file_size = os.path.getsize(file_path)
        app.logger.debug(f"Uploading file {file_path} ({file_size} bytes) to gofile.io")
        
        timeout = 300 if file_size > 100 * 1024 * 1024 else 120
        
        with open(file_path, 'rb') as f:
            files = {'file': f}
            r = requests.post('https://store1.gofile.io/uploadFile', files=files, timeout=timeout)
            
            if r.status_code != 200:
                app.logger.error(f"Gofile upload failed with status {r.status_code}: {r.text}")
                return None, f"Upload service returned error {r.status_code}"
            
            res = r.json()
            
            if res.get('status') != 'ok':
                error_msg = res.get('error', 'Unknown upload error')
                app.logger.error(f"Gofile upload failed: {error_msg}")
                return None, error_msg
                
            if 'data' not in res or 'downloadPage' not in res['data']:
                app.logger.error(f"Unexpected gofile response format: {res}")
                return None, "Unexpected response format from upload service"
                
            return res['data']['downloadPage'], None
            
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return None, f"Upload error: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    try:
        file_path = os.path.join('/tmp', filename)
        if not os.path.exists(file_path):
            app.logger.error(f"File not found: {file_path}")
            abort(404)
        if not filename.endswith('.ipa'):
            app.logger.error(f"Invalid file type requested: {filename}")
            abort(400)
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        abort(500)

@app.route('/sign', methods=['POST'])
def sign_ipa():
    try:
        ipa = request.files.get('ipa')
        p12 = request.files.get('p12')
        provision = request.files.get('provision')
        password = request.form.get('password')

        if not all([ipa, p12, provision, password]):
            return jsonify({'error': 'Missing one or more required fields'}), 400
        
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

            bundle_id, app_name = extract_bundle_and_name(ipa_path)

            cmd = [
                ZSIGN_PATH,
                '-k', p12_path,
                '-p', password,
                '-m', provision_path,
                '-o', output_path,
                ipa_path
            ]
            app.logger.debug(f"Running zsign command: {' '.join(cmd)}")
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

            signed_filename = f"signed_{bundle_id}_{int(time.time())}.ipa"
            permanent_path = os.path.join('/tmp', signed_filename)
            shutil.copy2(output_path, permanent_path)

            file_size_mb = round(os.path.getsize(permanent_path) / (1024*1024), 2)
            app.logger.debug(f"Signed IPA size: {file_size_mb} MB")

            ipa_url, err = upload_to_gofile(output_path)
            if err:
                app.logger.warning(f"Upload IPA failed: {err}")
                return jsonify({
                    'success': True,
                    'message': 'App signed, dar uploadul IPA a esuat.',
                    'direct_download': f'/download/{signed_filename}'
                })

            manifest_content = generate_manifest(bundle_id, app_name, ipa_url)
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(manifest_content)

            manifest_url, manifest_err = upload_to_gofile(manifest_path)
            if manifest_err:
                app.logger.warning(f"Upload manifest failed: {manifest_err}")
                return jsonify({
                    'success': True,
                    'message': 'App semnat, IPA incarcat, dar upload manifest a esuat.',
                    'direct_download': f'/download/{signed_filename}'
                })

            itms_services_url = f"itms-services://?action=download-manifest&url={manifest_url}"

            return jsonify({
                'success': True,
                'message': 'App semnat și incarcat cu succes!',
                'itms_services_url': itms_services_url,
                'direct_download': f'/download/{signed_filename}',
                'app_info': {
                    'name': app_name,
                    'bundle_id': bundle_id,
                    'size_mb': file_size_mb
                }
            })

    except subprocess.CalledProcessError as e:
        return jsonify({'error': 'Semnarea a eșuat', 'details': e.output}), 500
    except Exception as e:
        return jsonify({'error': 'Eroare neașteptată', 'details': str(e)}), 500

if __name__ == '__main__':
    if os.path.exists(ZSIGN_PATH):
        os.chmod(ZSIGN_PATH, 0o755)
    app.run(host='0.0.0.0', port=5000, debug=True)
