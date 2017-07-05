# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~

    A microblogging application written with Flask

    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import time
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash
from werkzeug import check_password_hash, generate_password_hash


# configuration
DEBUG = True
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

# create our little application :)
app = Flask('minitwit')
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

# initialize data
all_users = {}
all_messages = []


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def robohash(username, size=80):
    """Return the Robohash image for the given username."""
    return 'https://robohash.org/%s.png?size=%dx%d' % \
        (username, size, size)


@app.before_request
def before_request():
    g.current_username = None
    if 'username' in session and session['username'] in all_users:
        g.current_username = session['username']


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.current_username:
        return redirect(url_for('public_timeline'))
    messages = []
    for message in all_messages:
        if message['author'] == g.current_username or message['author'] in all_users[g.current_username]['following']:
            messages.append(message)
    return render_template('timeline.html', messages=messages)


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    return render_template('public_timeline.html', messages=all_messages)


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    if not username in all_users:
        abort(404)
    followed = False
    if g.current_username and username in all_users[g.current_username]['following']:
        followed = True
    messages = []
    for message in all_messages:
        if message['author'] == username:
            messages.append(message)
    return render_template('user_timeline.html', messages=messages, followed=followed,
            profile_username=username)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.current_username:
        abort(401)
    if not username in all_users:
        abort(404)
    all_users[g.current_username]['following'].append(username)
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.current_username:
        abort(401)
    if not username in all_users:
        abort(404)
    all_users[g.current_username]['following'].remove(username)
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if not g.current_username:
        abort(401)
    if request.form['text']:
        all_messages.insert(0, {
            'author': g.current_username,
            'text': request.form['text'],
            'pub_date': int(time.time()),
        })
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.current_username:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        current_username = request.form['username']
        if not current_username in all_users:
            error = 'Invalid username'
        elif not check_password_hash(all_users[current_username]['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['username'] = current_username
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.current_username:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif request.form['username'] in all_users:
            error = 'The username is already taken'
        else:
            username = request.form['username']
            all_users[username] = {
                'pw_hash': generate_password_hash(request.form['password']),
                'following': []
            }
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('username', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['robohash'] = robohash
