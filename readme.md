_Catalog App_
============

## Project Overview :
Develop a web application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

### "catalog" Database Structure :

| Table | Descriptions | Columns |
|--------|-----------------|------------|
| **user** | information about the users | name, email, picture, id |
| **category** | information about the categories | name, id |
| **item** | information about the items added by users | name, description, id, cat_id, user_id |

## Approach :
- Use the Python framework **Flask** to develop a RESTful web application.
- Implement third-pary OAuth authentication. (**Google** and **Facebook**)
- Use the Python SQL toolkit **SQLAlchemy** to build the database.
- Map proper HTTP methods to **CRUD** (create, read, update and delete) operations.

## Usage (localhost) :
1. The virtual machine.
    - From the command line, navigate to the folder containing the Vagrantfile
    - Power up the virtual machine by typing: `vagrant up` (note: this may take a couple minutes to complete)
    - Once the virtual machine is done booting, log into it by typing: `vagrant ssh`
2. Setup the "catalog" database and initialize with some data.
    - Navigate to "catalog" folder
    - From the command line, type `python initial_data.py`
3. Launch the application.
    - From the command line, type `python views.py`
4. Accessing the application.
    - Open a web browser and type `http://localhost:8000` or `http://0.0.0.0:8000` on the address bar
5. Endpoints
    - Access `http://localhost:8000/catalog/<data>.json` where `<data>` can be `catalog`, `category`, `item`, or `user`

## Usage (live site) :
- [Catalog App](http://catalog.youngwookbaek.com)
