from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from .models import User, db, Match, PasswordResetToken
from . import mail
from datetime import datetime
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import secrets
import string
from sqlalchemy import or_

main = Blueprint('main', __name__)

@main.route('/')
def home():
    users = User.query.filter_by(enabled=True).order_by(User.elo.desc()).all()
    matches = Match.query.order_by(Match.date_played.desc()).limit(10).all()
    return render_template('home.html', users=users, matches=matches)

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email').lower()
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('main.register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('main.register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        msg = Message(
            subject="New Registration Approval Needed",
            sender="darts@cafejojo.nl",
            recipients=["cafejojo@soep.org"],
            body=(
            f"New user registered: {username} ({email})\n\n"
            f"To enable this user, click the following link:\n"
            f"{url_for('main.enable_user', user_id=user.id, _external=True)}"
            )
        )
        mail.send(msg)
        
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['username']
        password = request.form['password']
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()
        if user and user.check_password(password):
            if not user.enabled:
                flash('Your account is not enabled. Please wait for approval.')
                return redirect(url_for('main.login'))
            login_user(user)
            return redirect(url_for('main.home'))
        else:
            flash('Invalid username/email or password.')
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@main.route('/record', methods=['GET', 'POST'])
@login_required
def record():
    if request.method == 'GET':
        users = User.query.filter_by(enabled=True).order_by(User.username).all()
        return render_template('record_match.html', users=users)
    return redirect(url_for('main.matches'))

@main.route('/record_match', methods=['POST'])
@login_required
def record_match():
    winner_id = request.form.get('winner')
    loser_id = request.form.get('loser')
    
    if winner_id == loser_id:
        flash('Winner and loser cannot be the same player')
        return redirect(url_for('main.record'))

    if not current_user.admin:
        if (int(winner_id) != current_user.id) and (int(loser_id) != current_user.id):
            flash('You can only record matches for yourself.')
            return redirect(url_for('main.record'))

    winner = User.query.get(winner_id)
    loser = User.query.get(loser_id)
    
    if winner and loser:
        k = 32
        expected_win = 1 / (1 + 10 ** ((loser.elo - winner.elo) / 400))
        expected_loss = 1 / (1 + 10 ** ((winner.elo - loser.elo) / 400))
        
        winner_elo_gain = int(k * (1 - expected_win))
        loser_elo_loss = int(k * (0 - expected_loss))
        
        winner.elo += winner_elo_gain
        new_loser_elo = loser.elo + loser_elo_loss
        if new_loser_elo < 101:
            loser_elo_loss = -(loser.elo - 101)  # Adjust the loss to reach exactly 101
            new_loser_elo = 101
        loser.elo = new_loser_elo
        
        # Update last played time
        winner.last_played = datetime.utcnow()
        loser.last_played = datetime.utcnow()
        
        # Get statistics from the form
        winner_180s = int(request.form.get('winner_180s', 0))
        loser_180s = int(request.form.get('loser_180s', 0))
        winning_finish = int(request.form.get('winning_finish', 0))
        
        # Update user statistics
        winner.matches_played += 1
        winner.matches_won += 1
        winner.one_eighties += winner_180s
        if winning_finish >= 100:
            winner.high_finishes += 1
        if winning_finish > winner.highest_finish:
            winner.highest_finish = winning_finish

        loser.matches_played += 1
        loser.matches_lost += 1
        loser.one_eighties += loser_180s
        
        match = Match(
            winner_id=winner.id,
            loser_id=loser.id,
            winner_elo_gain=winner_elo_gain,
            loser_elo_loss=loser_elo_loss,
            date_played=datetime.utcnow(),
            recorded_by=current_user.id,
            winner_180s=winner_180s,
            loser_180s=loser_180s,
            winning_finish=winning_finish
        )
        db.session.add(match)
        db.session.commit()
    
    return redirect(url_for('main.home'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.admin:
            flash('Admin access required.')
            return redirect(url_for('main.home'))
        return f(*args, **kwargs)
    return decorated_function

@main.route('/admin')
@login_required
@admin_required
def admin():
    users = User.query.order_by(User.username).all()
    return render_template('admin.html', users=users)

@main.route('/admin/enable_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def enable_user(user_id):
    if not current_user.admin:
        flash('Admin access required.')
        return redirect(url_for('main.home'))
    user = User.query.get(user_id)
    if user:
        user.enabled = True
        db.session.commit()
        flash(f'User {user.username} has been enabled.')
    else:
        flash('User not found.')
    return redirect(url_for('main.home'))

@main.route('/admin/user/<int:user_id>/enable', methods=['POST'])
@login_required
@admin_required
def admin_enable_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.enabled = True
        db.session.commit()
        flash(f'User {user.username} has been enabled.')
    return redirect(url_for('main.admin'))

@main.route('/admin/user/<int:user_id>/disable', methods=['POST'])
@login_required
@admin_required
def admin_disable_user(user_id):
    if user_id == current_user.id:
        flash('You cannot disable your own account.')
        return redirect(url_for('main.admin'))
    
    user = User.query.get(user_id)
    if user:
        user.enabled = False
        db.session.commit()
        flash(f'User {user.username} has been disabled.')
    return redirect(url_for('main.admin'))

@main.route('/admin/user/<int:user_id>/make-admin', methods=['POST'])
@login_required
@admin_required
def admin_make_admin(user_id):
    user = User.query.get(user_id)
    if user:
        user.admin = True
        db.session.commit()
        flash(f'{user.username} is now an admin.')
    return redirect(url_for('main.admin'))

@main.route('/admin/user/<int:user_id>/remove-admin', methods=['POST'])
@login_required
@admin_required
def admin_remove_admin(user_id):
    if user_id == current_user.id:
        flash('You cannot remove your own admin rights.')
        return redirect(url_for('main.admin'))
    
    user = User.query.get(user_id)
    if user:
        user.admin = False
        db.session.commit()
        flash(f'Admin rights removed from {user.username}.')
    return redirect(url_for('main.admin'))

@main.route('/admin/user/<int:user_id>/reset-elo', methods=['POST'])
@login_required
@admin_required
def admin_reset_elo(user_id):
    user = User.query.get_or_404(user_id)
    user.elo = 1000
    db.session.commit()
    flash(f'Reset ELO rating for {user.username}')
    return redirect(url_for('main.admin'))

@main.route('/admin/user/<int:user_id>/set-elo', methods=['POST'])
@login_required
@admin_required
def admin_set_elo(user_id):
    user = User.query.get_or_404(user_id)
    try:
        new_elo = int(request.form.get('elo', 1000))
        if new_elo < 0:
            raise ValueError("ELO cannot be negative")
        user.elo = new_elo
        db.session.commit()
        flash(f'Updated ELO rating for {user.username} to {new_elo}')
    except (ValueError, TypeError):
        flash('Invalid ELO value provided')
    return redirect(url_for('main.admin'))

@main.route('/admin/user/<int:user_id>/remove', methods=['POST'])
@login_required
@admin_required
def admin_remove_user(user_id):
    user = User.query.get_or_404(user_id)
    # Optionally: Prevent removing yourself or the last admin
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} has been removed.', 'success')
    return redirect(url_for('main.admin'))

@main.route('/matches')
def matches():
    page = request.args.get('page', 1, type=int)
    player_id = request.args.get('player', type=int)
    
    query = Match.query
    if player_id:
        query = query.filter((Match.winner_id == player_id) | (Match.loser_id == player_id))
    
    matches = query.order_by(Match.date_played.desc()).paginate(
        page=page,
        per_page=20,
        error_out=False
    )
    
    users = User.query.filter_by(enabled=True).order_by(User.username).all()
    return render_template('matches.html', matches=matches, users=users)

@main.route('/stats')
def stats():
    player_id = request.args.get('player', type=int)
    users = User.query.filter_by(enabled=True).order_by(User.elo.desc()).all()
    selected_player = None
    high_finishes = []
    recent_180s = []
    
    if player_id:
        selected_player = User.query.get(player_id)
        if selected_player:
            # Get high finishes (100+)
            high_finishes = Match.query.filter(
                Match.winner_id == player_id,
                Match.winning_finish >= 100
            ).order_by(Match.date_played.desc()).limit(10).all()
            
            # Get matches with 180s
            recent_180s = Match.query.filter(
                ((Match.winner_id == player_id) & (Match.winner_180s > 0)) |
                ((Match.loser_id == player_id) & (Match.loser_180s > 0))
            ).order_by(Match.date_played.desc()).limit(10).all()
    
    return render_template('stats.html', 
                         users=users, 
                         selected_player=selected_player,
                         high_finishes=high_finishes,
                         recent_180s=recent_180s)

@main.route('/scores')
def scores():
    # Get all enabled users ordered by matches played
    users = User.query.filter_by(enabled=True).order_by(
        db.func.coalesce(User.matches_played, 0).desc()
    ).all()
    
    # Get recent matches with 180s
    recent_180s = Match.query.filter(
        db.or_(
            Match.winner_180s > 0,
            Match.loser_180s > 0
        )
    ).order_by(Match.date_played.desc()).limit(10).all()
    
    # Get high finishes
    high_finishes = Match.query.filter(
        db.and_(
            Match.winning_finish.isnot(None),
            Match.winning_finish >= 100
        )
    ).order_by(
        Match.winning_finish.desc(), 
        Match.date_played.desc()
    ).limit(10).all()
    
    # Calculate average finishes for each user
    user_avg_finishes = {}
    for user in users:
        avg_finish = db.session.query(
            db.func.avg(Match.winning_finish)
        ).filter(
            Match.winner_id == user.id,
            Match.winning_finish.isnot(None),
            Match.winning_finish > 0
        ).scalar()
        user_avg_finishes[user.id] = avg_finish if avg_finish is not None else 0
    
    return render_template('scores.html',
                         users=users,
                         recent_180s=recent_180s,
                         high_finishes=high_finishes,
                         user_avg_finishes=user_avg_finishes)

@main.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Verify current password
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html')
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
        
        # Check password length
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('change_password.html')
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('main.home'))
    
    return render_template('change_password.html')

@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Create a password reset token
            reset_token = PasswordResetToken(user.id)
            db.session.add(reset_token)
            db.session.commit()
            
            # Send email with reset link
            try:
                reset_url = url_for('main.reset_password', token=reset_token.token, _external=True)
                msg = Message(
                    subject="ELOdarts - Password Reset",
                    sender="darts@cafejojo.nl",
                    recipients=[email],
                    body=(
                    f"Hello {user.username},\n\n"
                    f"You have requested to reset your password. Please click the link below to set a new password:\n\n"
                    f"{reset_url}\n\n"
                    f"This link will expire in 1 hour for security reasons.\n"
                    f"If you did not request this change, please ignore this email.\n\n"
                    f"Best regards,\n\n"
                    f"Cafe Jojo Ranking Darts Team\n"
                    )
                )
                mail.send(msg)
                flash('If an account with that email exists, a password reset link has been sent.', 'info')
            except Exception as e:
                flash('Error sending email. Please try again later.', 'error')
                
        else:
            # Don't reveal if email exists or not for security
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        
        return redirect(url_for('main.login'))
    
    return render_template('forgot_password.html')

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or not reset_token.is_valid():
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('main.forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Check password length
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        user = reset_token.user
        user.password_hash = generate_password_hash(new_password)
        reset_token.mark_as_used()
        db.session.commit()
        
        flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('reset_password.html', token=token)

@main.route('/api/elo_history/<int:user_id>')
def elo_history(user_id):
    user = User.query.get_or_404(user_id)
    
    # Get all matches for this player, ordered by date
    matches = Match.query.filter(
        or_(Match.winner_id == user_id, Match.loser_id == user_id)
    ).order_by(Match.date_played.asc()).all()
    
    # Start with initial ELO (assuming starting ELO is 501)
    current_elo = 501  # Starting ELO
    dates = []
    elo_values = []
    
    # Add starting point
    if matches:
        # Calculate what the starting ELO would have been by working backwards
        # from current ELO and all the match changes
        total_change = 0
        for match in matches:
            if match.winner_id == user_id:
                total_change += match.winner_elo_gain
            else:
                total_change += match.loser_elo_loss
        
        starting_elo = user.elo - total_change
        current_elo = starting_elo
        
        # Add initial point
        dates.append("Start")
        elo_values.append(current_elo)
    
    # Process each match
    for match in matches:
        if match.winner_id == user_id:
            # Player won - add the ELO gain
            current_elo += match.winner_elo_gain
        else:
            # Player lost - add the ELO loss (which should be negative)
            current_elo += match.loser_elo_loss
        
        dates.append(match.date_played.strftime('%Y-%m-%d'))
        elo_values.append(current_elo)
    
    return jsonify({
        'dates': dates,
        'elo_values': elo_values
    })

