import requests
import time
import uvicorn
import hashlib
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.simpledialog import askstring
from fastapi import FastAPI, Body, HTTPException, status
from pydantic import BaseModel
from threading import Thread
from typing import Annotated

import uvicorn.server

# Base model for user class
class BaseUser(BaseModel):
    name: str
    surname: str|None = None
    username: str
    age: int|None = None
    comments: str|None = None
    user_id: int

class User(BaseUser):
    pass

# For making hashed password invisible when listing users' data
class UserFull(BaseUser):
    password: str

app = FastAPI()

# users dict (a kind of simplest database)
users = {}

logged_users = set()

def hash_pasword(password):

    # Hashes plain text password

    hash = hashlib.new('sha256')
    hash.update(str.encode(password))
    digest = hash.hexdigest()
    return digest

@app.get('/')
async def get():
    return {'message': 'This is simple application using tkinter and fastapi. Visit http://127.0.0.1:8000/docs for more information.'}


@app.post('/users/', response_model=User)
async def create_user(user_id: Annotated[int, Body(ge=0)],
                      name: Annotated[str, Body(min_length=3)],
                      username: Annotated[str, Body(min_length=3)],
                      password: Annotated[str, Body(min_length=8)],
                      surname: Annotated[str|None, Body()]=None,  
                      age: Annotated[int|None, Body(ge=18)]=None,
                      comments: Annotated[str|None, Body()]=None):
    
    # Creating user and putting him into the dictionary database

    if username in users:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f'User {username} already exists in database!')
    hashed_password = hash_pasword(password=password)
    user = UserFull(
        user_id=user_id,
        name=name,
        username=username,
        password=hashed_password,
        surname=surname,
        age=age,
        comments=comments
    )
    users[username] = user
    return user

@app.get('/users/', response_model=dict[str, User])
async def get_all_users():
    # Get all users
    return users

@app.get('/users/{user_id}', response_model=User)
async def get_user(user_id: str):
    
    # Get user by his user_id

    if user_id not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'User {user_id} not found!')
    return users[user_id]

@app.post('/user-login/')
async def user_login(username: Annotated[str, Body()], password: Annotated[str, Body()]):
    """Loging user using his username and password"""
    if username not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'User {username} not found!')
    if username in logged_users:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f'User {username} already loged in!')
    if users[username].password != password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Wrong password!')
    logged_users.add(username)

    return {'message': f'Welcome, {username}!'}

@app.put('/logout/{username}')
async def logout(username: str):
    # User logout
    if username not in logged_users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'User not logged!')
    logged_users.remove(username)
    return {'message': f'{username} logged off!'}
    

class MainWindow:

    """This class creates main application window, its handlers and handles requests from its side."""

    def __init__(self):
        self.window = tk.Tk()
        self.window.geometry('800x600+400+400')
        self.window.protocol('WM_DELETE_WINDOW', self.quit)

        # creates and starts uvicorn server in separate thread
        self.base_url = 'http://127.0.0.1:8000'
        config = uvicorn.Config(app=app, host='127.0.0.1', port=8000)
        self.server = uvicorn.Server(config=config)
        self.server_thread = Thread(target=self.server.run, name='uvicorn_server')
        self.server_thread.start()

        # Bool variable for controling counters
        self.counter_check = False

        # Starting value for user_id of the database items
        self.id = 0


        self.create_widgets()

        self.window.mainloop()



    def quit(self):

        # Stops counters, stops server and exits

        self.counter_check = False
        if self.server_thread.is_alive():
            self.server.should_exit = True
        
        self.window.destroy()

    def create_widgets(self):

        # Widget creation

        x_0 = 20
        y_0 = 20

        dx = 120
        dy = 50

        width = 100
        height = 40

        x = x_0
        y = y_0

        """
        First it creates two buttons and two text fields.
        Clicking buttons starts two counters working in separate threads.
        Conuters' statuses are displayed in text fields
        
        The same method is used for starting both counters.

        I have made this two counters just to practice with multithreading with tkinter 
        and to learn how to deal with eventual issues.
        """

        self.count_1 = tk.StringVar()
        btn_count_1 = tk.Button(master=self.window, text='Counter_1')
        btn_count_1.bind('<Button-1>', func=lambda event, arg=self.count_1: self.start_counter(event, arg))
        btn_count_1.place(x=x, y=y, width=width, height=height)

        x += dx
        txt_count_1 = tk.Entry(master=self.window, textvariable=self.count_1, justify='center')
        txt_count_1.place(x=x, y=y, width=width, height=height)
        self.count_1.set('0')

        x += dx
        self.count_2 = tk.StringVar()
        btn_count_2 = tk.Button(master=self.window, text='Counter_2')
        btn_count_2.bind('<Button-1>', func=lambda event, arg=self.count_2: self.start_counter(event, arg))
        btn_count_2.place(x=x, y=y, width=width, height=height)

        x += dx
        txt_count_2 = tk.Entry(master=self.window, textvariable=self.count_2, justify='center')
        txt_count_2.place(x=x, y=y, width=width, height=height)
        self.count_2.set('0')

        """
        In the next frame are fields for entering database items for user: name, surname, age, username, password and age.
        """

        x = x_0
        y += dy + y_0
        y_t = y

        frame = ttk.Frame(master=self.window, relief='groove', border=2)
        frame.place(x=x, y=y, width=800 - 2 * x_0, height= 3 * dy + 2 * y_0)

        lbl_frame = tk.Label(master=self.window, text='User Data', border=2, relief='ridge')
        lbl_frame.place(x = x + x_0, y=y-12, width=90, height=25)

        x = 0
        y = y_0

        lbl_name = tk.Label(master=frame, text='Name:', anchor='e')
        lbl_name.place(x=x, y=y, width=width, height=height)
        
        x += dx
        self.name = tk.StringVar()
        txt_name = tk.Entry(master=frame, justify='center', textvariable=self.name)
        txt_name.place(x=x, y=y, width=width, height=height)

        x += dx
        lbl_surname = tk.Label(master=frame, text='Surname:', anchor='e')
        lbl_surname.place(x=x, y=y, width=width, height=height)
        
        x += dx
        self.sur_name = tk.StringVar()
        txt_sur_name = tk.Entry(master=frame, justify='center', textvariable=self.sur_name)
        txt_sur_name.place(x=x, y=y, width=width, height=height)

        x += dx
        lbl_age = tk.Label(master=frame, text='Age:', anchor='e')
        lbl_age.place(x=x, y=y, width=width, height=height)
        
        x += dx
        self.age = tk.StringVar()
        txt_age = tk.Entry(master=frame, justify='center', textvariable=self.age)
        txt_age.place(x=x, y=y, width=width, height=height)

        x = 0
        y += dy

        lbl_username = tk.Label(master=frame, text='Username:', anchor='e')
        lbl_username.place(x=x, y=y, width=width, height=height)
        
        x += dx
        self.username = tk.StringVar()
        txt_username = tk.Entry(master=frame, justify='center', textvariable=self.username)
        txt_username.place(x=x, y=y, width=width, height=height)

        x += dx
        lbl_password = tk.Label(master=frame, text='Password:', anchor='e')
        lbl_password.place(x=x, y=y, width=width, height=height)
        
        x += dx
        self.password = tk.StringVar()
        txt_password= tk.Entry(master=frame, justify='center', textvariable=self.password, show='*')
        txt_password.place(x=x, y=y, width=width, height=height)

        x = 0
        y += dy

        lbl_comment = tk.Label(master=frame, text='Comment:', anchor='e')
        lbl_comment.place(x=x, y=y, width=width, height=height)

        x += dx
        self.comment = tk.StringVar()
        txt_comment = tk.Entry(master=frame, justify='right', textvariable=self.comment)
        txt_comment.place(x=x, y=y, width= 6  * width, height=height)


        """
        Here are buttons for creating user, adding it to the database, logging, and displaying them
        """

        x = x_0
        y = y_t + 3 * dy + 3 * y_0

        btn_add_user = tk.Button(self.window, text='Add User', command=self.add_user)
        btn_add_user.place(x=x, y=y, width=width, height=height)

        # Displaying user by id
        x += dx
        btn_get_user = tk.Button(self.window, text='Get User', command=self.get_user)
        btn_get_user.place(x=x, y=y, width=width, height=height)

        # Displaying all users
        x += dx
        btn_all_users = tk.Button(self.window, text='Get All Users', command=self.get_all_users)
        btn_all_users.place(x=x, y=y, width=width, height=height)

        x = x_0
        y += dy
        btn_login = tk.Button(master=self.window, text='Login', command=self.user_login)
        btn_login.place(x=x, y=y, width=width, height=height)

        x += dx
        btn_logout = tk.Button(master=self.window, text='Logout', command=self.user_logout)
        btn_logout.place(x=x, y=y, width=width, height=height)



    def start_counter(self, event, txt_box):
        """
        This method starts counter in separate thread. 
        Arguments for thread creation are the buttton which started the counter and the text field for data display.
        Clicks on both buttons starts this method.
        event.widget is associated for the button that was clicked
        txt_box  the stringvar associated with the appropriate text field for displaying counter.
        """
        new_thread = Thread(target=self.counter, args=[event.widget, txt_box])
        new_thread.start()

    """
    This is counter that counts to 30 and every 0.2 seconds displays current value in the text field.
    During the counting, button that started the thread is disabled.
    Before the beginning of the loop, self.counter_check variable is set to True
    If we exit application while counter is running, the self.counter_check varible is set to false in the self.quit() method, 
    which immediately exits the counter.
    Without this, button state would be set from disabled to normal, even if application is exited before. 
    This leads to error if main thread exited and window with all its widgets is destroyed before changing button's state.
    This variable prevents this.
    """

    def counter(self, widget, txt_box):
        start = int(txt_box.get())
        self.counter_check = True
        widget['state'] = 'disabled'
        for num in range(start, start + 30):
            if not self.counter_check:
                return
            txt_box.set(num)
            time.sleep(0.2)
        widget['state'] = 'normal'


    def get_data(self):
        # Reading fields with user data
        return {
            'user_id': self.id,
            'name': self.name.get(),
            'username': self.username.get(),
            'password': self.password.get(),
            'surname': self.sur_name.get(),
            'age': self.age.get(),
            'comments': self.comment.get()
        }
    
    def clear_fields(self):
            # Clearing fields with user data after user is succesfully created
            self.name.set('')
            self.username.set('')
            self.password.set('')
            self.sur_name.set('')
            self.age.set('')
            self.comment.set('')
        

    def process_error_message(self, error_json):
        # This function extracts and returns information from error message to get clear view what went wrong.
        detail = error_json['detail'][0]
        txt = f'Field {detail['loc'][1].capitalize()}: {detail['msg']}'
        return txt



    def add_user(self):
        # Requesting creating user from data and putting it to the database
        url = self.base_url + '/users/'
        data = self.get_data()
        response = requests.post(url=url, json=data)
        if response.status_code == 200:
            print(f'User {self.username.get()} succesfuly added!' )
            self.id += 1
            self.clear_fields()
        else:
            err = response.json()
            ans = self.process_error_message(err)
            print(ans)
  

    def get_user(self):
        # Dispalays user data based on his username
        username = askstring(title='Get username', prompt='Enter username: ')
        if not username:
            return 
        url = self.base_url + f'/users/{username}'
        response = requests.get(url)
        if response.status_code == 200:
            print(response.text)
        else:
            print(response.json()['detail'])

    def get_all_users(self):
        # Displays all users
        url = self.base_url + '/users/'
        response = requests.get(url=url)
        if response.status_code == 200:
            user_list = response.json()
            for key, value in user_list.items():
                print(f'{key}: {value}')
        else:
            print(response.json()['detail'])

    def user_login(self):
        """
        User login
        Username and password are enterd in the separate window
        Password is hashed before returning to main window.

        If something went long during the loging, the appropriate message is displayed
        """
        dialog = LoginDialog(self.window)
        self.window.wait_window(dialog.login_window)
        if not dialog.result:
            return
        
        username = dialog.result['username']
        password = dialog.result['password']
     
        url = self.base_url + '/user-login/'
        
        # Maybe it's not the most secure way to log in, but I am still learning
        response = requests.post(url, json={'username': username, 'password': password}, params={'p': 'protected'})
        
        if response.status_code == 200:
            print(response.json()['message'])
        else:
            print(response.json()['detail'])

    def user_logout(self):
        """
        User logout
        if the user doesn't exist or is not logged in, appropriate message is displayed
        """
        username = askstring(title='Logout User', prompt='Username:')
        if not username:
            return
        url = self.base_url + f'/logout/{username}'
        response = requests.put(url=url)
        
        if response.status_code == 200:
            print(response.json()['message'])
        else:
            print(response.json()['detail'])
        
        


class LoginDialog:
    """
    Class that handles creation of the new window for entering username and passwotd for user log in.
    This window is created on the top of the main window.
    It consist of the labels, two text fields and two buttons.
    Before returning to the main application, password is hashed.

    """
    def __init__(self, master):
        self.login_window = tk.Toplevel(master=master)
        self.login_window.title('User Login')
        self.login_window.geometry('200x250+500+500')

        self.login_window.grab_set()
        
        x_0 = 20
        y_0 =20
        dy = 50
        width = 160
        height= 40

        x = x_0
        y = y_0
        lbl_username = tk.Label(master=self.login_window, text='Username')
        lbl_username.place(x=x, y=y, width=width, height=height)

        y += dy - 20
        self.username = tk.StringVar()
        txt_username = tk.Entry(master=self.login_window, textvariable=self.username)
        txt_username.place(x=x, y=y, width=width, height=height)

        y += dy
        lbl_password = tk.Label(master=self.login_window, text='Password')
        lbl_password.place(x=x, y=y, width=width, height=height)

        y += dy - 20
        self.password = tk.StringVar()
        txt_password = tk.Entry(master=self.login_window, textvariable=self.password, show='*')
        txt_password.place(x=x, y=y, width=width, height=height)

        y += dy
        btn_ok = tk.Button(master=self.login_window, text='OK', command=self.ok)
        btn_ok.place(x=x, y=y, width=width // 2, height=height)

        x += width // 2 + 5
        btn_cancel = tk.Button(master=self.login_window, text='Cancel', command=self.cancel)
        btn_cancel.place(x=x, y=y, width=width // 2, height=height)

        txt_username.focus()

    def hash_pasword(password):
        # Password hashing
        hash = hashlib.new('sha256')
        hash.update(str.encode(password))
        digest = hash.hexdigest()
        return digest

    def cancel(self):
        # Button Cancel is pressed
        self.result = None
        self.login_window.destroy()

    def ok(self):
        """
        Button OK is pressed.
        First it checks is there input in the text fields.
        """
        if self.username.get() == '' or self.password.get() == '':
            return
        self.result = {
            'username': self.username.get(),
            'password': hash_pasword(self.password.get())
        }
        self.login_window.destroy()


if __name__ == '__main__':
    window = MainWindow()