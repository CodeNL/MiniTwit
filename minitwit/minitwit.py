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

def get_next_user_id():
    """Generate new user id."""
    max_id = 0

    for user_id in all_users:
        if int(user_id) > max_id:
            max_id = int(user_id)
    return str(max_id + 1)

def get_user_id(username):
    """Convenience method to look up the id for a username."""
    for user_id, user in all_users.items():
        if user['username'] == username:
            return user_id
    return None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def robohash(username, size=80):
    """Return the Robohash image for the given username."""
    return 'https://robohash.org/%s.png?size=%dx%d' % \
        (username, size, size)


@app.before_request
def before_request():
    g.current_user_id = None
    if 'user_id' in session and session['user_id'] in all_users:
        g.current_user = all_users[session['user_id']]
        g.current_user_id = session['user_id']


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.current_user_id:
        return redirect(url_for('public_timeline'))
    messages = []
    for message in all_messages:
        if message['author_id'] == g.current_user_id or message['author_id'] in all_users[g.current_user_id]['following']:
            messages.append(message)
    return render_template('timeline.html', messages=messages)


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    return render_template('public_timeline.html', messages=all_messages)


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    followed = False
    if g.current_user_id and whom_id in all_users[g.current_user_id]['following']:
        followed = True
    messages = []
    for message in all_messages:
        if message['author_id'] == whom_id:
            messages.append(message)
    return render_template('user_timeline.html', messages=messages, followed=followed,
            profile_user=all_users[whom_id])


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.current_user_id:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    all_users[g.current_user_id]['following'].append(whom_id)
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.current_user_id:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    all_users[g.current_user_id]['following'].remove(whom_id)
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if not g.current_user_id:
        abort(401)
    if request.form['text']:
        all_messages.insert(0, {
            'author_id': g.current_user_id,
            'text': request.form['text'],
            'pub_date': int(time.time()),
            'username': all_users[g.current_user_id]['username']
        })
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.current_user_id:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        current_user_id = None
        for user_id, user in all_users.items():
            if user['username'] == request.form['username']:
                current_user_id = user_id
        if current_user_id is None:
            error = 'Invalid username'
        elif not check_password_hash(all_users[current_user_id]['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = current_user_id
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.current_user_id:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            user_id = get_next_user_id()
            all_users[user_id] = {
                'username': request.form['username'],
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
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['robohash'] = robohash
