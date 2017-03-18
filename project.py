from flask import (Flask, render_template,
                   request, redirect, url_for, flash, jsonify)
app = Flask(__name__)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets, AccessTokenCredentials
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app.secret_key = 'A0Zr98j/3yX R~dfgHH!jmNdfgLWX/,?RT'

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///item_catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def index():
    categories = session.query(Category).all()
    return render_template('index.html', categories=categories,
                           is_user=isUser(login_session))


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', state=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain Authorization Code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid
    access_token = credentials.access_token
    url ='https://www.googleapis.com/oauth2/v1/tokeninfo?access_token='
    url = url + access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If threre was an error in the access token, return 500 internal server
    # error
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesnt match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID doesnt match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if the user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps("Current user is already connected."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # store the access token in the session
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # If the user doesnt already exist in the DB, create one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px; \
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected user
    credentials = AccessTokenCredentials.from_json(
        login_session['credentials'])
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute GET request to revoke current token.
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token='
    url = url + access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset the user's session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        flash('Successfully disconnected.')
        return redirect('/')

    else:
        # If we receive anything other than a 200 response from google, aassume
        # invalid token
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/category/<int:category_id>/')
def categoryItems(category_id):
    categories = session.query(Category).all()
    items = session.query(Item).filter_by(category_id=category_id).all()

    category_selected = None
    for cat in categories:
        if cat.id == category_id:
            category_selected = cat
    owner = getUserInfo(category_selected.user_id)

    if 'username' not in login_session or owner.id != login_session['user_id']:
        return render_template('category.html',
                               items=items,
                               categories=categories,
                               category_selected=category_selected,
                               is_user=isUser(login_session))
    else:
        return render_template('category_owner.html',
                               items=items,
                               categories=categories,
                               category_selected=category_selected,
                               is_user=isUser(login_session))


@app.route('/category/<int:category_id>/<int:item_id>/')
def viewItem(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).first()
    owner = getUserInfo(item.user_id)

    if 'username' not in login_session or owner.id != login_session['user_id']:
        return render_template('item.html', item=item,
            is_user=isUser(login_session))
    else:
        return render_template('item_owner.html', item = item,
            is_user=isUser(login_session))


@app.route('/category/<int:category_id>/new/', methods=['GET', 'POST'])
def newCategoryItem(category_id):
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newItem = Item(
            name=request.form['name'],
            price=request.form['price'],
            description=request.form['description'],
            category_id=category_id,
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        return redirect('/category/' + str(category_id))
    else:
        return render_template('newitem.html',
                               is_user=isUser(login_session))

@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newCat = Category(name=request.form['name'],
                          user_id=login_session['user_id'])
        session.add(newCat)
        session.commit()
        return redirect('/category/' + str(newCat.id))
    else:
        return render_template('newcategory.html',
                               is_user=isUser(login_session))


@app.route('/category/<int:category_id>/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editCatrgoryItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')

    item = session.query(Item).filter_by(id=item_id).first()
    owner = getUserInfo(item.user_id)

    if request.method == "POST" and owner.id == login_session['user_id']:
        item.name = request.form['name']
        item.price = request.form['price']
        item.picture = request.form['picture']
        item.description = request.form['description']
        session.commit()
        return redirect('/category/' + str(category_id))
    else:
        if ('username' not in login_session
                or owner.id != login_session['user_id']):
            flash("You do not have permission to edit this item.")
            return redirect('/')
        else:
            return render_template('edititem.html', item=item,
                                   is_user=isUser(login_session))


@app.route('/category/<int:category_id>/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteCategotyItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')

    item = session.query(Item).filter_by(id=item_id).first()
    owner = getUserInfo(item.user_id)

    if request.method == "POST" and owner.id == login_session['user_id']:
        session.delete(item)
        session.commit()
        return redirect('/category/' + str(category_id))
    else:
        if ('username' not in login_session
                or owner.id != login_session['user_id']):
            flash("You do not have permission to delete this item.")
            return redirect('/')
        else:
            return render_template('deleteitem.html', item=item,
                                   is_user=isUser(login_session))

# Making an API endpoint for category items


@app.route('/category/<int:category_id>/JSON')
def categoryJSON(category_id):
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def isUser(login_session):
    if not login_session:
        return False
    if 'username' not in login_session:
        return False
    else:
        return True

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
