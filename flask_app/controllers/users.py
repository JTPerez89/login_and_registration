from flask_app import app
from flask import render_template,redirect,request,session,flash
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def landing():
    return render_template('index.html')

@app.route('/success')
def success():
    if 'id' not in session:
        flash("Must be logged in to access that page.")
        return redirect('/')
    user = User.select_id({'id': session['id']})
    return render_template('success.html', user=user)

@app.route('/new_user', methods=['post'])
def new_user():
    is_valid = User.validate_reg(request.form)
    if is_valid == True:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        data = {
        "first_name" : request.form["first_name"],
        "last_name" : request.form["last_name"],
        "email" : request.form["email"],
        "password" : pw_hash
        }
        user_id = User.save(data)
        session['user_id'] = user_id
    return redirect('/success')

@app.route('/login', methods=['post'])
def login():
    print(session)
    if not User.validate_login(request.form):
        return redirect('/')
    return redirect('/success')

@app.route('/clear', methods=['post'])
def clear():
    session.clear()
    return redirect('/')