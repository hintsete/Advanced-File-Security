
import os
from app import app  # your existing import

BASE_DIR = os.path.abspath(os.path.dirname(__file__))  # app folder path
UPLOAD_FOLDER = os.path.join(BASE_DIR, '..', 'uploads')  # uploads folder at project root
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# You might also want ALLOWED_EXTENSIONS if not already set:
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'docx', 'png', 'jpg', 'jpeg', 'gif', 'bin'}



from flask import render_template, request, redirect, url_for, flash, send_from_directory, send_file
from app import app
from app.crypto_utils import (
    generate_random_hex, encrypt_file, decrypt_file,
    generate_hmac, check_ecb_pattern_leak,
    simulate_replay_attack, brute_force_demo
)
# import os
from werkzeug.utils import secure_filename
from datetime import datetime


# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if file part is present
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Create timestamped filename for uniqueness
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            original_filename = secure_filename(file.filename)
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"original_{timestamp}_{original_filename}")
            file.save(input_path)

            # Get parameters or generate defaults
            cipher_type = request.form.get('cipher_type', 'aes-128-cbc')
            key = request.form.get('key') or generate_random_hex(16)
            iv = request.form.get('iv') or (generate_random_hex(16) if cipher_type.endswith('cbc') else None)

            # Output filename for encrypted file
            output_filename = f"encrypted_{timestamp}_{original_filename}.bin"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            # Encrypt the file
            result = encrypt_file(input_path, output_path, cipher_type, key, iv)

            if result.returncode != 0:
                flash(f'Encryption failed: {result.stderr}', 'error')
                return redirect(request.url)

            # Generate HMAC for integrity verification
            hmac = generate_hmac(output_path, key)

            # Return success page with all relevant details
            return render_template(
                'result.html',
                original_filename=original_filename,
                encrypted_filename=output_filename,
                cipher=cipher_type,
                key=key,
                iv=iv,
                hmac=hmac
            )
    return render_template('index.html')


@app.route('/encryption_results')
def encryption_results():
    details = request.cookies.get('encryption_details', '').split('|')
    if len(details) != 6:
        flash('Encryption details not found', 'error')
        return redirect(url_for('index'))

    return render_template('result.html',
                           original_file=details[0],
                           encrypted_file=details[1],
                           cipher_type=details[2],
                           key=details[3],
                           iv=details[4] if details[4] else None,
                           hmac=details[5])


@app.route('/ecb_demo', methods=['GET', 'POST'])
def ecb_demo():
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No image file selected', 'error')
            return redirect(request.url)

        image = request.files['image']
        if image.filename == '':
            flash('No image selected', 'error')
            return redirect(request.url)

        if image and allowed_file(image.filename):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            original_filename = secure_filename(image.filename)
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"ecb_original_{timestamp}_{original_filename}")
            image.save(input_path)

            # ECB encrypted output
            ecb_filename = f"ecb_encrypted_{timestamp}_{original_filename}.bin"
            ecb_path = os.path.join(app.config['UPLOAD_FOLDER'], ecb_filename)

            # CBC encrypted output for comparison
            cbc_filename = f"cbc_encrypted_{timestamp}_{original_filename}.bin"
            cbc_path = os.path.join(app.config['UPLOAD_FOLDER'], cbc_filename)

            # Run ECB encryption and pattern check (returns key used)
            key = check_ecb_pattern_leak(input_path, ecb_path)

            # CBC encryption for comparison with random IV
            iv = generate_random_hex(16)
            encrypt_file(input_path, cbc_path, 'aes-128-cbc', key, iv)

            return render_template('ecb_results.html',
                                   original_image=original_filename,
                                   ecb_image=ecb_filename,
                                   cbc_image=cbc_filename,
                                   key=key,
                                   iv=iv)
    return render_template('ecb_demo.html')


@app.route('/replay_demo', methods=['GET', 'POST'])
def replay_demo():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            original_filename = secure_filename(file.filename)
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"replay_original_{timestamp}_{original_filename}")
            file.save(input_path)

            output1 = os.path.join(app.config['UPLOAD_FOLDER'], f"replay1_{timestamp}_{original_filename}.bin")
            output2 = os.path.join(app.config['UPLOAD_FOLDER'], f"replay2_{timestamp}_{original_filename}.bin")

            # Simulate replay attack and get result dict
            result = simulate_replay_attack(input_path, output1, output2)

            return render_template('replay_results.html',
                                   original_file=original_filename,
                                   encrypted_file1=os.path.basename(output1),
                                   encrypted_file2=os.path.basename(output2),
                                   key=result['key'],
                                   iv=result['iv'],
                                   files_identical=result['files_identical'])
    return render_template('replay_demo.html')


@app.route('/bruteforce_demo', methods=['GET', 'POST'])
def bruteforce_demo():
    if request.method == 'POST':
        original_text = request.form.get('text', 'Hello World')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ciphertext_path = os.path.join(app.config['UPLOAD_FOLDER'], f'bruteforce_{timestamp}.bin')

        result = brute_force_demo(ciphertext_path, original_text)

        return render_template('bruteforce_results.html',
                               success=result['success'],
                               found_key=result.get('found_key'),
                               decrypted_text=result.get('decrypted_text'),
                               total_attempts=result['total_attempts'],
                               original_text=original_text)
    return render_template('bruteforce_demo.html')


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            encrypted_filename = secure_filename(file.filename)
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypt_input_{timestamp}_{encrypted_filename}")
            file.save(input_path)

            cipher_type = request.form.get('cipher_type')
            key = request.form.get('key')
            iv = request.form.get('iv')

            if not key:
                flash('Decryption key is required', 'error')
                return redirect(request.url)

            output_filename = f"decrypted_{timestamp}_{encrypted_filename.replace('.bin', '')}"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            result = decrypt_file(input_path, output_path, cipher_type, key, iv)

            if result.returncode != 0:
                flash(f'Decryption failed: {result.stderr}', 'error')
                return redirect(request.url)

            hmac = request.form.get('hmac')
            if hmac:
                calculated_hmac = generate_hmac(input_path, key)
                hmac_valid = (hmac == calculated_hmac)
            else:
                hmac_valid = None

            response = send_file(
                output_path,
                as_attachment=True,
                download_name=output_filename
            )

            response.set_cookie('decryption_details',
                                value=f"{encrypted_filename}|{output_filename}|{cipher_type}|{hmac_valid}",
                                max_age=60)

            return response

    return render_template('decrypt.html')


@app.route('/decryption_results')
def decryption_results():
    details = request.cookies.get('decryption_details', '').split('|')
    if len(details) != 4:
        flash('Decryption details not found', 'error')
        return redirect(url_for('decrypt'))

    return render_template('decrypt_results.html',
                           encrypted_file=details[0],
                           decrypted_file=details[1],
                           cipher_type=details[2],
                           hmac_valid=details[3] if details[3] != 'None' else None)


@app.route('/download/<filename>')
def download(filename):
    folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
    print("Serving from folder:", folder)
    filepath = os.path.join(folder, filename)
    print("Full file path:", filepath)
    if not os.path.exists(filepath):
        print("File not found!")
    return send_from_directory(folder, filename, as_attachment=True)



@app.route('/view/<filename>')
def view_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/cleanup', methods=['POST'])
def cleanup():
    try:
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                flash(f'Error deleting {filename}: {str(e)}', 'error')

        flash('All temporary files have been deleted', 'success')
    except Exception as e:
        flash(f'Cleanup failed: {str(e)}', 'error')

    return redirect(url_for('index'))

# from flask import render_template, request, redirect, url_for, flash, send_from_directory, send_file
# from app import app
# from app.crypto_utils import (
#     generate_random_hex, encrypt_file, decrypt_file,
#     generate_hmac, check_ecb_pattern_leak,
#     simulate_replay_attack, brute_force_demo
# )
# import os
# from werkzeug.utils import secure_filename
# from datetime import datetime
#
# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
#
# @app.route('/', methods=['GET', 'POST'])
# def index():
#     if request.method == 'POST':
#         if 'file' not in request.files:
#             flash('No file selected', 'error')
#             return redirect(request.url)
#
#         file = request.files['file']
#         if file.filename == '':
#             flash('No file selected', 'error')
#             return redirect(request.url)
#
#         if file and allowed_file(file.filename):
#             # Create timestamped filenames
#             timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#             original_filename = secure_filename(file.filename)
#             input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"original_{timestamp}_{original_filename}")
#             file.save(input_path)
#
#             # Get encryption parameters
#             cipher_type = request.form.get('cipher_type', 'aes-128-cbc')
#             key = request.form.get('key') or generate_random_hex(16)
#             iv = request.form.get('iv') or (generate_random_hex(16) if cipher_type.endswith('cbc') else None)
#
#             # Prepare output filename
#             output_filename = f"encrypted_{timestamp}_{original_filename}.bin"
#             output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
#
#             # Encrypt file
#             result = encrypt_file(input_path, output_path, cipher_type, key, iv)
#
#             if result.returncode != 0:
#                 flash(f'Encryption failed: {result.stderr}', 'error')
#                 return redirect(request.url)
#
#             # Generate HMAC for integrity check
#             hmac = generate_hmac(output_path, key)
#
#             # Return both the download and the results page
#             response = send_file(
#                 output_path,
#                 as_attachment=True,
#                 download_name=output_filename,
#                 mimetype='application/octet-stream'
#             )
#
#             # Set cookies with encryption details for the results page
#             response.set_cookie('encryption_details',
#                               value=f"{original_filename}|{output_filename}|{cipher_type}|{key}|{iv or ''}|{hmac}",
#                               max_age=60)
#
#             return response
#
#     return render_template('index.html')
#
# @app.route('/encryption_results')
# def encryption_results():
#     details = request.cookies.get('encryption_details', '').split('|')
#     if len(details) != 6:
#         flash('Encryption details not found', 'error')
#         return redirect(url_for('index'))
#
#     return render_template('result.html',
#                          original_file=details[0],
#                          encrypted_file=details[1],
#                          cipher_type=details[2],
#                          key=details[3],
#                          iv=details[4] if details[4] else None,
#                          hmac=details[5])
#
# @app.route('/ecb_demo', methods=['GET', 'POST'])
# def ecb_demo():
#     if request.method == 'POST':
#         if 'image' not in request.files:
#             flash('No image file selected', 'error')
#             return redirect(request.url)
#
#         image = request.files['image']
#         if image.filename == '':
#             flash('No image selected', 'error')
#             return redirect(request.url)
#
#         if image and allowed_file(image.filename):
#             # Create timestamped filenames
#             timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#             original_filename = secure_filename(image.filename)
#             input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"ecb_original_{timestamp}_{original_filename}")
#             image.save(input_path)
#
#             # Generate output filenames
#             ecb_filename = f"ecb_encrypted_{timestamp}_{original_filename}.bin"
#             ecb_path = os.path.join(app.config['UPLOAD_FOLDER'], ecb_filename)
#
#             cbc_filename = f"cbc_encrypted_{timestamp}_{original_filename}.bin"
#             cbc_path = os.path.join(app.config['UPLOAD_FOLDER'], cbc_filename)
#
#             # Perform encryption and pattern check
#             key = check_ecb_pattern_leak(input_path, ecb_path)
#
#             # Also encrypt with CBC for comparison
#             iv = generate_random_hex(16)
#             encrypt_file(input_path, cbc_path, 'aes-128-cbc', key, iv)
#
#             return render_template('ecb_results.html',
#                                  original_image=original_filename,
#                                  ecb_image=ecb_filename,
#                                  cbc_image=cbc_filename,
#                                  key=key,
#                                  iv=iv)
#
#     return render_template('ecb_demo.html')
#
# @app.route('/replay_demo', methods=['GET', 'POST'])
# def replay_demo():
#     if request.method == 'POST':
#         if 'file' not in request.files:
#             flash('No file selected', 'error')
#             return redirect(request.url)
#
#         file = request.files['file']
#         if file.filename == '':
#             flash('No file selected', 'error')
#             return redirect(request.url)
#
#         if file and allowed_file(file.filename):
#             # Create timestamped filenames
#             timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#             original_filename = secure_filename(file.filename)
#             input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"replay_original_{timestamp}_{original_filename}")
#             file.save(input_path)
#
#             # Generate output filenames
#             output1 = os.path.join(app.config['UPLOAD_FOLDER'], f"replay1_{timestamp}_{original_filename}.bin")
#             output2 = os.path.join(app.config['UPLOAD_FOLDER'], f"replay2_{timestamp}_{original_filename}.bin")
#
#             # Simulate replay attack
#             result = simulate_replay_attack(input_path, output1, output2)
#
#             return render_template('replay_results.html',
#                                 original_file=original_filename,
#                                 encrypted_file1=os.path.basename(output1),
#                                 encrypted_file2=os.path.basename(output2),
#                                 key=result['key'],
#                                 iv=result['iv'],
#                                 files_identical=result['files_identical'])
#
#     return render_template('replay_demo.html')
#
# @app.route('/bruteforce_demo', methods=['GET', 'POST'])
# def bruteforce_demo():
#     if request.method == 'POST':
#         original_text = request.form.get('text', 'Hello World')
#         timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#         ciphertext_path = os.path.join(app.config['UPLOAD_FOLDER'], f'bruteforce_{timestamp}.bin')
#
#         result = brute_force_demo(ciphertext_path, original_text)
#
#         return render_template('bruteforce_results.html',
#                             success=result['success'],
#                             found_key=result.get('found_key'),
#                             decrypted_text=result.get('decrypted_text'),
#                             total_attempts=result['total_attempts'],
#                             original_text=original_text)
#
#     return render_template('bruteforce_demo.html')
#
# @app.route('/decrypt', methods=['GET', 'POST'])
# def decrypt():
#     if request.method == 'POST':
#         if 'file' not in request.files:
#             flash('No file selected', 'error')
#             return redirect(request.url)
#
#         file = request.files['file']
#         if file.filename == '':
#             flash('No file selected', 'error')
#             return redirect(request.url)
#
#         if file and allowed_file(file.filename):
#             # Create timestamped filename
#             timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#             encrypted_filename = secure_filename(file.filename)
#             input_path = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypt_input_{timestamp}_{encrypted_filename}")
#             file.save(input_path)
#
#             cipher_type = request.form.get('cipher_type')
#             key = request.form.get('key')
#             iv = request.form.get('iv')
#
#             if not key:
#                 flash('Decryption key is required', 'error')
#                 return redirect(request.url)
#
#             # Prepare output filename
#             output_filename = f"decrypted_{timestamp}_{encrypted_filename.replace('.bin', '')}"
#             output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
#
#             # Decrypt file
#             result = decrypt_file(input_path, output_path, cipher_type, key, iv)
#
#             if result.returncode != 0:
#                 flash(f'Decryption failed: {result.stderr}', 'error')
#                 return redirect(request.url)
#
#             # Verify HMAC if provided
#             hmac = request.form.get('hmac')
#             if hmac:
#                 calculated_hmac = generate_hmac(input_path, key)
#                 hmac_valid = (hmac == calculated_hmac)
#             else:
#                 hmac_valid = None
#
#             # Return both the download and the results page
#             response = send_file(
#                 output_path,
#                 as_attachment=True,
#                 download_name=output_filename
#             )
#
#             # Set cookies with decryption details
#             response.set_cookie('decryption_details',
#                               value=f"{encrypted_filename}|{output_filename}|{cipher_type}|{hmac_valid}",
#                               max_age=60)
#
#             return response
#
#     return render_template('decrypt.html')
#
# @app.route('/decryption_results')
# def decryption_results():
#     details = request.cookies.get('decryption_details', '').split('|')
#     if len(details) != 4:
#         flash('Decryption details not found', 'error')
#         return redirect(url_for('decrypt'))
#
#     return render_template('decrypt_results.html',
#                          encrypted_file=details[0],
#                          decrypted_file=details[1],
#                          cipher_type=details[2],
#                          hmac_valid=details[3] if details[3] != 'None' else None)
#
# @app.route('/download/<filename>')
# def download(filename):
#     return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
#
# @app.route('/view/<filename>')
# def view_file(filename):
#     return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
#
# @app.route('/cleanup', methods=['POST'])
# def cleanup():
#     try:
#         for filename in os.listdir(app.config['UPLOAD_FOLDER']):
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             try:
#                 if os.path.isfile(file_path):
#                     os.unlink(file_path)
#             except Exception as e:
#                 flash(f'Error deleting {filename}: {str(e)}', 'error')
#
#         flash('All temporary files have been deleted', 'success')
#     except Exception as e:
#         flash(f'Cleanup failed: {str(e)}', 'error')
#
#     return redirect(url_for('index'))