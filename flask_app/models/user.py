from flask_app.config.mysqlconnection import connectToMySQL
import re
from flask_app import app
from flask import flash, session
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

class User:
    def __init__( self , data ):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']


    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        results = connectToMySQL('login_and_reg_schema').query_db(query)
        users = []
        for user in results:
            users.append( cls(user) )
        return users

    @classmethod
    def save(cls, data):
        query = 'INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());'
        return connectToMySQL('login_and_reg_schema').query_db(query, data)

    @classmethod
    def delete(cls, data):
        query = 'DELETE FROM users WHERE id = %(id)s;'
        return connectToMySQL('login_and_reg_schema').query_db(query, {'id':data})

    @classmethod
    def select(cls, data):
        query = 'SELECT * FROM users WHERE email = %(email)s'
        results =  connectToMySQL('login_and_reg_schema').query_db(query, data)
        if results:
            return cls (results[0])

    @classmethod
    def select_id(cls, data):
        query = 'SELECT * FROM users WHERE id = %(id)s'
        results =  connectToMySQL('login_and_reg_schema').query_db(query, data)
        if results:
            return cls (results[0])

    @classmethod
    def select_last(cls):
        query = 'SELECT * FROM users ORDER BY id DESC LIMIT 1;'
        return connectToMySQL('login_and_reg_schema').query_db(query)
    
    @classmethod
    def update(cls, data):
        query = 'UPDATE users SET name = %(first_name)s, %(last_name)s, %(email)s, %(password)s updated_at = NOW() WHERE id = %(id)s;'
        return connectToMySQL('login_and_reg_schema').query_db(query, data)


    @staticmethod
    def validate_login(data):
        is_valid = True

        if is_valid:
            potential_user = User.select(data)
            if potential_user:
                if not bcrypt.check_password_hash(potential_user.password, data['password']):
                    flash('Invalid password/email.')
                    is_valid = False
                else:
                    print(potential_user.id)
                    session['id'] = potential_user.id
            else:
                is_valid = False
                flash("Invalid password/email.")
        return is_valid


    @staticmethod
    def validate_reg(data):
        is_valid = True
        if len(data['first_name']) < 2:
            flash("First name must be at least 2 characters.")
            is_valid = False
        if not data['first_name'].isalpha():
            flash('First name must only contain alphabetic characters.')
            is_valid = False
        if len(data['last_name']) < 2:
            flash("Last Name must be at least 2 characters.")
            is_valid = False
        if not data['last_name'].isalpha():
            flash('Last name must only contain alphabetic characters.')
            is_valid = False
        if len(data['email']) < 1:
            flash("Email must be at least 2 characters.")
            is_valid = False
        if not EMAIL_REGEX.match(data['email']): 
            flash("Invalid email address!")
            is_valid = False
        if len(data['password']) < 8:
            flash("Password must be at least 8 characters.")
            is_valid = False
        if data['password'] != data['confirm']:
            flash("Password and confirm password do not match.")
            is_valid = False
        return is_valid