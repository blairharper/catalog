from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Department, Minister

app = Flask(__name__)

# Connect to database and store session in accessible variable
engine = create_engine('sqlite:///govdeptministers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Dev user info
user_id = "1"


# Routing for home page to list all departments
# TODO: ADD RECENTLY ADDED MINISTERS
@app.route('/')
@app.route('/departments/')
def showDepartments():
    departments = session.query(Department).all()
    return render_template('departments.html', departments=departments)


# Route to create new department page, also handles post method to save to db
@app.route('/department/new/', methods=['GET', 'POST'])
def newDepartment():
    if request.method == 'POST':
        newDepartment = Department(name=request.form['name'], user_id=user_id)
        session.add(newDepartment)
        session.commit()
        return redirect(url_for('showDepartments'))
    return render_template('newdepartment.html')


@app.route('/department/<int:dept_id>/edit/', methods=['GET', 'POST'])
def editDepartment(dept_id):
    dept = session.query(Department).filter_by(id=dept_id).one()
    if request.method == 'POST':
        dept.name = request.form['name']
        session.commit()
        return redirect(url_for('showDepartments'))
    return render_template('editdepartment.html', dept=dept)


@app.route('/department/<int:dept_id>/delete/', methods=['GET', 'POST'])
def deleteDepartment(dept_id):
    dept = session.query(Department).filter_by(id=dept_id).one()
    if request.method == 'POST':
        session.delete(dept)
        session.commit()
        return redirect(url_for('showDepartments'))
    return render_template('deletedepartment.html', dept=dept)


@app.route('/department/<int:dept_id>/ministers/')
def showMinisters(dept_id):
    ministers = session.query(Minister).filter_by(dept_id=dept_id).all()
    dept = session.query(Department).filter_by(id=dept_id).one()
    return render_template('ministers.html', dept=dept,
                           ministers=ministers)


# Route to create new minister page, also handles post request to save to db
@app.route('/department/<int:dept_id>/minister/new/', methods=['GET', 'POST'])
def newMinister(dept_id):
    if request.method == 'POST':
        newMinister = Minister(name=request.form['name'],
                               const=request.form['const'], dept_id=dept_id)
        session.add(newMinister)
        session.commit()
        return redirect(url_for('showMinisters', dept_id=dept_id))
    return render_template('newminister.html', dept_id=dept_id)


@app.route('/department/<int:dept_id>/minister/<int:minst_id>/edit/',
           methods=['GET', 'POST'])
def editMinister(dept_id, minst_id):
    minst = session.query(Minister).filter_by(id=minst_id).one()
    if request.method == 'POST':
        minst.name = request.form['name']
        minst.const = request.form['const']
        session.commit()
        return redirect(url_for('showMinisters', dept_id=dept_id))
    return render_template('editminister.html', dept_id=dept_id,
                           minst=minst)


@app.route('/department/<int:dept_id>/minister/<int:minst_id>/delete/',
           methods=['GET', 'POST'])
def deleteMinister(dept_id, minst_id):
    minst = session.query(Minister).filter_by(id=minst_id).one()
    if request.method == 'POST':
        session.delete(minst)
        session.commit()
        return redirect(url_for('showMinisters', dept_id=dept_id))
    return render_template('deleteminister.html', dept_id=dept_id,
                           minst=minst)


@app.route('/login/')
def showLogin():
    return render_template('login.html')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
