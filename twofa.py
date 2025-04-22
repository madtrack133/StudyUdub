# twofa.py
import pyotp
import qrcode
from io import BytesIO
from flask import Blueprint, render_template, request, redirect, flash, session, current_app, url_for
from flask_login import login_required, current_user
from models import db

# Blueprint mounted at /twofa
twofa_bp = Blueprint('twofa', __name__, url_prefix='/twofa')

@twofa_bp.route('/', methods=['GET', 'POST'])
@login_required
def twofa():
    # Use the logged-in user from Flask-Login
    user = current_user

    # Initialize TOTP secret if not set
    if not user.twofa_secret:
        user.twofa_secret = pyotp.random_base32()
        db.session.commit()

    # Build provisioning URI and generate QR
    totp = pyotp.TOTP(user.twofa_secret)
    issuer = current_app.config.get('TWOFA_ISSUER_NAME', 'StudyUdub')
    uri = totp.provisioning_uri(user.email, issuer_name=issuer)

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    qr_data = buf.getvalue()

    # Handle token submission
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        if totp.verify(token):
            session['twofa_authenticated'] = True
            flash('Two-Factor authentication successful.')
            # Redirect to next URL if exists, else dashboard
            next_url = session.pop('next_url', None) or url_for('dashboard')
            return redirect(next_url)
        flash('Invalid authentication code.')

    return render_template('twofa.html', qr_data=qr_data)
