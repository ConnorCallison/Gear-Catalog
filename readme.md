# Gear Catelog

In this project I used Flask to build a web application that could showcase my favorite gear.

----------
 - Features
 - Google sign in
 - JSON endpoint
 - Users can create categories
 - Users can create, edit, and delete items.

Files
-------------
> - **project.py** This file is the heart of the catalog, it handles all of the get / post requests and interfaces with the database to provide categories, items, Google Login, and  editing / deleting data.
> - **db_setup.py** This file creates the database by leveraging the Python library SQLAlchemy. (https://www.sqlalchemy.org/)
> - **/templates** each file in this folder is an HTML template for one of the pages. They are rendered by Flask.

## Usage
1. Clone this repository
2. Create an OAuth Client ID at https://console.developers.google.com
3. Open the Client ID and click "Download JSON"
4. Place the downloaded file in the same directory as project.py and rename it as `client_secrets.json`
5. Run the command ```python project.py ```
6. You're in action! Access the catalog by visiting http://localhost:8000
