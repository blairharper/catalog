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
engine = create_engine('postgresql://ukgovcat:PASSWORD@localhost/ukgovcat')
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
@app.route('/ministers/JSON/')
def ministersJSON():
    ministers = session.query(Minister).all()
    return jsonify(Ministers=[m.serialise for m in ministers])


# End point for all ministers of given department
@app.route('/department/<int:dept_id>/ministers/JSON/')
def deptMinistersJSON(dept_id):
    ministers = session.query(Minister).filter_by(dept_id=dept_id).all()
    return jsonify(DepartmentMinisters=[m.serialise for m in ministers])


# End point for a single given department
@app.route('/department/<int:dept_id>/JSON/')
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
    # the *_auth variables tell the page which CRUD functions to enable links
    # for. Could be merged into single auth variable or just use logged_in
    # but kept separate to allow greater flexibility. Same for showMinisters.
    credentials = login_session.get('credentials')
    if credentials is None:
        logged_in = 'False'
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        logged_in = 'False'
        add_auth = 'False'
        edit_auth = 'False'
        delete_auth = 'False'
    else:
        logged_in = 'True'
        add_auth = 'True'
        edit_auth = 'True'
        delete_auth = 'True'
    departments = session.query(Department).order_by(asc(Department.name))
    ministers = session.query(Minister).order_by(desc(Minister.id)).limit(5)
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
    if request.method == 'POST':
        newDepartment = Department(name=request.form['name'],
                                   user_id=login_session['user_id'])
        session.add(newDepartment)
        session.commit()
        return redirect(url_for('showDepartments'))
    # Check user is logged in, only logged in users can create items
    if 'username' not in login_session:
        flash("You are not authorised to perform this action. "
              "Please login.")
        return redirect(url_for('showLogin'))
    else:
        return render_template('newdepartment.html')
    # If post request then process request to create db entry


# Route to edit a department
@app.route('/department/<int:dept_id>/edit/', methods=['GET', 'POST'])
def editDepartment(dept_id):
    # If post request then process request to amend db entry
    if request.method == 'POST':
        dept = session.query(Department).filter_by(id=dept_id).one()
        dept.name = request.form['name']
        session.commit()
        return redirect(url_for('showDepartments'))
    # Check user is logged in, only logged in users can edit items
    if 'username' not in login_session:
        flash("You are not authorised to perform this action. "
              "Please login.")
        return redirect(url_for('showLogin'))
    # Check user is authorised to edit this dept using helper method.
    auth = isAuthorised(login_session['user_id'], dept_id, 'Department')
    if auth == 'True':
        dept = session.query(Department).filter_by(id=dept_id).one()
        return render_template('editdepartment.html', dept=dept)
    else:
        flash("Error: You may only edit departments you created.")
        return redirect(url_for('showDepartments'))


# Route to delete a department
@app.route('/department/<int:dept_id>/delete/', methods=['GET', 'POST'])
def deleteDepartment(dept_id):
    # Process any post requests.
    if request.method == 'POST':
        dept = session.query(Department).filter_by(id=dept_id).one()
        minst = session.query(Minister).filter_by(dept_id=dept_id).all()
        session.delete(dept)
        session.commit()
    # Also need to delete any ministers associated with dept
        for m in minst:
            session.delete(m)
            session.commit()
        return redirect(url_for('showDepartments'))
    # Check user is logged in, only logged in users can edit items
    if 'username' not in login_session:
        flash("You are not authorised to perform this action. "
              "Please login.")
        return redirect(url_for('showLogin'))
    # Check user is authorised to delete this dept using helper method.
    auth = isAuthorised(login_session['user_id'], dept_id, 'Department')
    if auth == 'True':
        dept = session.query(Department).filter_by(id=dept_id).one()
        return render_template('deletedepartment.html', dept=dept)
    else:
        flash("Error: you may only delete departments you created.")
        return redirect(url_for('showDepartments'))


# Route to show ministers of given department
@app.route('/department/<int:dept_id>/ministers/')
def showMinisters(dept_id):
    # Check if user is logged in so template renders correct login/logout links
    credentials = login_session.get('credentials')
    if credentials is None:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        add_auth = 'False'
        edit_auth = 'False'
        delete_auth = 'False'
    else:
        add_auth = 'True'
        edit_auth = 'True'
        delete_auth = 'True'
    try:
        ministers = session.query(Minister).filter_by(dept_id=dept_id).all()
        dept = session.query(Department).filter_by(id=dept_id).one()
        return render_template('ministers.html', dept=dept,
                               ministers=ministers,
                               add_auth=add_auth,
                               edit_auth=edit_auth,
                               delete_auth=delete_auth)
    except NoResultFound:
        flash("Given department ID is not associated with any departments.")
        return redirect('/')


# Route to create new minister
@app.route('/department/<int:dept_id>/minister/new/', methods=['GET', 'POST'])
def newMinister(dept_id):
    # Process POST request and create DB entry
    if request.method == 'POST':
        newMinister = Minister(name=request.form['name'],
                               const=request.form['const'],
                               dept_id=dept_id,
                               user_id=login_session['user_id'])
        session.add(newMinister)
        session.commit()
        return redirect(url_for('showMinisters', dept_id=dept_id))
    # Check user is logged in before redirecting to new minister page
    if 'username' not in login_session:
        flash("You are not authorised to perform this action. "
              "Please login.")
        return redirect(url_for('showLogin'))
    else:
        return render_template('newminister.html', dept_id=dept_id)


# Route to edit minister details
@app.route('/department/<int:dept_id>/minister/<int:minst_id>/edit/',
           methods=['GET', 'POST'])
def editMinister(dept_id, minst_id):
    # Process POST request and amend db entry
    if request.method == 'POST':
        minst = session.query(Minister).filter_by(id=minst_id).one()
        minst.name = request.form['name']
        minst.const = request.form['const']
        session.commit()
        return redirect(url_for('showMinisters', dept_id=dept_id))
    # Check user is logged in before proceeding
    if 'username' not in login_session:
        flash("You are not authorised to perform this action. "
              "Please login.")
        return redirect(url_for('showLogin'))
    # Check user is authorised to edit minister using helper method.
    auth = isAuthorised(login_session['user_id'], minst_id, 'Minister')
    if auth == 'True':
        minst = session.query(Minister).filter_by(id=minst_id).one()
        return render_template('editminister.html', dept_id=dept_id,
                               minst=minst)
    else:
        flash("Error: you may only edit ministers you created.")
        return redirect(url_for('showMinisters', dept_id=dept_id))


# Route to delete minister
@app.route('/department/<int:dept_id>/minister/<int:minst_id>/delete/',
           methods=['GET', 'POST'])
def deleteMinister(dept_id, minst_id):
    # Process any POST requests and delete db entry
    if request.method == 'POST':
        minst = session.query(Minister).filter_by(id=minst_id).one()
        session.delete(minst)
        session.commit()
        return redirect(url_for('showMinisters', dept_id=dept_id))
    # Check user is logged in, only logged in users can edit items
    if 'username' not in login_session:
        flash("You are not authorised to perform this action. "
              "Please login.")
        return redirect(url_for('showLogin'))
    # Check user is authorised to delete this minister using helper method.
    auth = isAuthorised(login_session['user_id'], minst_id, 'Minister')
    if auth == 'True':
        minst = session.query(Minister).filter_by(id=minst_id).one()
        return render_template('deleteminister.html', dept_id=dept_id,
                               minst=minst)
    else:
        flash("Error: you may only delete minsters that you created.")
        return redirect(url_for('showMinisters', dept_id=dept_id))


# ////// Helper methods //////
# Helper method to add new user to db
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
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


# Helper method to check if user created an item
# and therefore if they have permission to edit that item
def isAuthorised(user_id, data_id, data_type):
    try:
        if data_type == 'Department':
            data = session.query(Department).filter_by(id=data_id).one()
        else:
            data = session.query(Minister).filter_by(id=data_id).one()
        data_owner = data.user_id
        if user_id == data_owner:
            return 'True'
        else:
            return 'False'
    except NoResultFound:
        flash("Something went wrong. Please contact us if problem persists.")
        return 'False'


# ////// End of Helper methods //////


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run()
