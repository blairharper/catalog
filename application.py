from flask import Flask, render_template, request, redirect, url_for, flash
from flask import jsonify
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, User, Department, Minister
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from six.moves import xrange

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']

# Connect to database and store session in accessible variable
engine = create_engine('sqlite:///govdeptministers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# RESTful (JSON) API end points:
# End point for all departments
@app.route('/departments/JSON/')
def departmentsJSON():
    departments = session.query(Department).all()
    return jsonify(Departments=[d.serialise for d in departments])


# End point for all ministers
def ministersJSON():
    ministers = session.query(Minister).all()
    return jsonify(Ministers=[m.serialise for m in ministers])


# End point for all ministers of given department
@app.route('/department/<int:dept_id>/ministers/JSON/')
def deptMinistersJSON(dept_id):
    ministers = session.query(Minister).filter_by(dept_id=dept_id).all()
    return jsonify(DepartmentMinisters=[m.serialise for m in ministers])


# End point for a single given department
@app.route('/department/JSON/')
def departmentJSON(dept_id):
    department = session.query(Department).one()
    return jsonify(Department=department.serialise)


# End point for a single given minister
@app.route('/department/<int:dept_id>/minister/<int:minst_id>/JSON/')
def ministerJSON(dept_id, minst_id):
    minister = session.query(Minister).filter_by(id=minst_id).one()
    return jsonify(Minister=minister.serialise)


# Login section (possibly move to separate file)
@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template(['login.html'], STATE=state)
# ////// End of API \\\\\\\


# Route for google authentication
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Make sure session state is set correctly before proceeding
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state.'))
        response.headers['Content-type'] = 'application/json'
        return response
    code = request.data
    try:
        # Read credentials from client_secrets and exchange for token
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to exchange authorisation'
                                            'code for credentials.'))
        response.headers['Content-type'] = 'application/json'
        return response
    # Store access token and authorise with googleapis
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If authorisation error occurred then return an error response
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-type'] = 'application/json'
        return response
    # Store user's g+ unique identifier
    gplus_id = credentials.id_token['sub']
    # Ensure our user ID matches the one in the token
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID does not match."),
                                 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # Ensure token has been issued for correct app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token ID doesn't match app's"))
        response.headers['Content-type'] = 'application/json'
        return response
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    # Compare current session with token credentials to see if user is already
    # logged in.
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps("User is already logged in."), 200)
        response.headers['Content-type'] = 'application/json'

    # Update session with login credentials/token
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Obtain user info from google api and parse into data variable
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    # Store user info in current session
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # Use helper method to check if user exists in database
    # If not create db entry
    if getUserID(login_session['email']) is None:
        createUser(login_session)

    # Store our user id from db in current session
    login_session['user_id'] = getUserID(login_session['email'])

    # Use isAuthorised helper method to check if user is admin
    if isAdmin(login_session['user_id']) == 'True':
        login_session['admin'] = 1
    else:
        login_session['admin'] = 0
    # Flash login message and return success response
    # (View function must return a response)
    response = 'Success'
    flash("you are logged in as %s" % login_session['username'])
    return response


# Route for logging out and terminating session
@app.route('/logout/')
def logout():
    # Check if user is logged in before attempting logout
    credentials = login_session.get('credentials')
    if credentials is None:
        flash("You are not logged in.")
        return redirect(url_for('showDepartments'))
    # Revoke user access token via google api
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # Destroy session data
    if result['status'] == '200':
        del login_session['username']
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['admin']
    # Send response
        flash("Logged out successfully")
        return redirect(url_for('showDepartments'))
    else:
        response = make_response(json.dumps("Something went wrong."), 401)
        response.headers['Content-type'] = 'application/json'
        flash("Something went wrong, please contact us if problem persists.")
        return redirect(url_for('showDepartments'))


# Routing for home page to list all departments
# TODO: ADD RECENTLY ADDED MINISTERS
@app.route('/')
@app.route('/departments/')
def showDepartments():
    # Check if user is logged in so template renders correct login/logout links
    credentials = login_session.get('credentials')
    if credentials is None:
        logged_in = 'False'
        print "TEST"
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
    else:
        logged_in = 'True'
    # Obtain permissions so template knows what links to provide user
    try:
        add_auth = isAuthorised('ADD')
        edit_auth = isAuthorised('EDIT')
        delete_auth = isAuthorised('DEL')
    # Throw exception if user not logged in and set all permissions to false
    except KeyError:
        add_auth = 'False'
        edit_auth = 'False'
        delete_auth = 'False'
    departments = session.query(Department).order_by(asc(Department.name))
    ministers = session.query(Minister).order_by(desc(Minister.id)).limit(5)
    print login_session['state']
    return render_template('departments.html', departments=departments,
                           ministers=ministers,
                           add_auth=add_auth,
                           edit_auth=edit_auth,
                           delete_auth=delete_auth,
                           logged_in=logged_in,
                           STATE=login_session['state'])


# Route to create new department page, also handles post method to save to db
@app.route('/department/new/', methods=['GET', 'POST'])
def newDepartment():
    # Check user is authorised to create new departments using helper method.
    try:
        auth = isAuthorised('ADD')
        # If post request then process request to create db entry
        if request.method == 'POST':
            newDepartment = Department(name=request.form['name'],
                                       user_id=login_session['user_id'])
            session.add(newDepartment)
            session.commit()
            return redirect(url_for('showDepartments'))
        if auth == 'True':
            return render_template('newdepartment.html')
        else:
            flash("You are not authorised to perform this action.")
            return redirect(url_for('showDepartments'))
    # Throw exception if user is not logged in.
    except KeyError:
        flash("You are not authorised to perform this action.")
        return redirect(url_for('showDepartments'))


# Route to edit a department
@app.route('/department/<int:dept_id>/edit/', methods=['GET', 'POST'])
def editDepartment(dept_id):
    # Check user is authorised to editdepartments using helper method.
    try:
        auth = isAuthorised('EDIT')
        dept = session.query(Department).filter_by(id=dept_id).one()
        # If post request then process request to amend db entry
        if request.method == 'POST':
            dept.name = request.form['name']
            session.commit()
            return redirect(url_for('showDepartments'))
        if auth == 'True':
            return render_template('editdepartment.html', dept=dept)
        else:
            flash("You are not authorised to perform this action.")
            return redirect(url_for('showDepartments'))
    # Throw exception if user is not logged in.
    except KeyError:
        flash("You are not authorised to perform this action.")
        return redirect(url_for('showDepartments'))


# Route to delete a department
@app.route('/department/<int:dept_id>/delete/', methods=['GET', 'POST'])
def deleteDepartment(dept_id):
    # Check user is authorised to delete epartments using helper method.
    try:
        auth = isAuthorised('DEL')
        dept = session.query(Department).filter_by(id=dept_id).one()
        ministers = session.query(Minister).filter_by(dept_id=dept_id).all()
        # If post request then process request to amend db entry
        if request.method == 'POST':
            session.delete(dept)
            session.commit()
            # Also need to delete any ministers associated with dept
            for m in ministers:
                session.delete(m)
                session.commit()
            return redirect(url_for('showDepartments'))
        if auth == 'True':
            return render_template('deletedepartment.html', dept=dept)
        else:
            flash("You are not authorised to perform this action.")
            return redirect(url_for('showDepartments'))
    # Throw exception if user is not logged in.
    except KeyError:
        flash("You are not authorised to perform this action.")
        return redirect(url_for('showDepartments'))


# Route to show ministers of given department
@app.route('/department/<int:dept_id>/ministers/')
def showMinisters(dept_id):
    # Check permissions so template knows what links to render
    try:
        add_auth = isAuthorised('ADD')
        edit_auth = isAuthorised('EDIT')
        delete_auth = isAuthorised('DEL')
    # Throw exception if user not logged in and set all permissions to false
    except KeyError:
        add_auth = 'False'
        edit_auth = 'False'
        delete_auth = 'False'
    ministers = session.query(Minister).filter_by(dept_id=dept_id).all()
    dept = session.query(Department).filter_by(id=dept_id).one()
    return render_template('ministers.html', dept=dept,
                           ministers=ministers,
                           add_auth=add_auth,
                           edit_auth=edit_auth,
                           delete_auth=delete_auth)


# Route to create new minister
@app.route('/department/<int:dept_id>/minister/new/', methods=['GET', 'POST'])
def newMinister(dept_id):
    # Check user is authorised to add ministers using helper method.
    try:
        auth = isAuthorised('ADD')
        # Process POST request and create DB entry
        if request.method == 'POST':
            newMinister = Minister(name=request.form['name'],
                                   const=request.form['const'],
                                   dept_id=dept_id)
            session.add(newMinister)
            session.commit()
            return redirect(url_for('showMinisters', dept_id=dept_id))
        if auth == 'True':
            return render_template('newminister.html', dept_id=dept_id)
        else:
            flash("You are not authorised to perform this action.")
            return redirect(url_for('showMinisters', dept_id=dept_id))
    # Throw exception if user is not logged in.
    except KeyError:
        flash("You are not authorised to perform this action.")
        return redirect(url_for('showMinisters', dept_id=dept_id))


# Route to edit minister details
@app.route('/department/<int:dept_id>/minister/<int:minst_id>/edit/',
           methods=['GET', 'POST'])
def editMinister(dept_id, minst_id):
    # Check user is authorised to edit ministers using helper method.
    try:
        auth = isAuthorised('EDIT')
        minst = session.query(Minister).filter_by(id=minst_id).one()
        # Process POST request and amend db entry
        if request.method == 'POST':
            minst.name = request.form['name']
            minst.const = request.form['const']
            session.commit()
            return redirect(url_for('showMinisters', dept_id=dept_id))
        if auth == 'True':
            return render_template('editminister.html', dept_id=dept_id,
                                   minst=minst)
        else:
            flash("You are not authorised to perform this action.")
            return redirect(url_for('showMinisters', dept_id=dept_id))
    # Throw exception if user is not logged in.
    except KeyError:
        flash("You are not authorised to perform this action.")
        return redirect(url_for('showMinisters', dept_id=dept_id))


# Route to delete minister
@app.route('/department/<int:dept_id>/minister/<int:minst_id>/delete/',
           methods=['GET', 'POST'])
def deleteMinister(dept_id, minst_id):
    # Check user is authorised to delete ministers using helper method.
    try:
        auth = isAuthorised('DEL')
        minst = session.query(Minister).filter_by(id=minst_id).one()
        # Process POST request and delete db entry
        if request.method == 'POST':
            session.delete(minst)
            session.commit()
            return redirect(url_for('showMinisters', dept_id=dept_id))
        if auth == 'True':
            return render_template('deleteminister.html', dept_id=dept_id,
                                   minst=minst)
        else:
            flash("You are not authorised to perform this action.")
            return redirect(url_for('showMinisters', dept_id=dept_id))
    # Throw exception if user is not logged in.
    except KeyError:
        flash("You are not authorised to perform this action.")
        return redirect(url_for('showMinisters', dept_id=dept_id))


# ////// Helper methods //////
# Helper method to add new user to db
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    # Grant first user created admin privelages (only admin can delete items)
    # THIS IS A TEMPORARY WORKAROUND IN ABSENCE OF AN ADMIN PORTAL
    # CREATION OF PROPER ADMIN PORTAL OUTWITH SCOPE OF THIS PROJECT
    if user.id == 1:
        user.admin = 1
        session.commit()
        login_session['admin'] = 1
    return user.id


# Helper method to grab user info from db
def getUserInfo(user_id):
    try:
        user = session.query(User).filter_by(id=user_id).one()
        return user
    except NoResultFound:
        return None


# Helper method to obtain user ID from db
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        return None


# Helper method to check if user has admin privelages
def isAdmin(user_id):
    try:
        user = getUserInfo(user_id)
        if user.admin == 1:
            return 'True'
        else:
            return 'False'
    except NoResultFound:
        return 'False'


# Function to check user has appropriate authority to carry out actions
# Helper method means permission levels can be changed quickly
# without having to rewrite other functions.
def isAuthorised(req_type):
    try:
        if req_type == "DEL" and login_session['admin'] == 1:
            return 'True'
        if req_type == 'ADD' and login_session['admin'] == 1:
            return 'True'
        if req_type == 'EDIT' and login_session['admin'] == 1:
            return 'True'
        else:
            return 'False'
        if req_type != 'DEL' or req_type != 'ADD' or req_type != 'EDIT':
            return 'Invalid request.'
    except AttributeError:
        return 'False'
# ////// End of Helper methods //////


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
