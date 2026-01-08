from website import create_app

app=create_app()

# only if we run main.py, we execute line 8
if __name__ == '__main__':
    # run flask app, start webserver. Debug = true : if we change code, automatically rerun webserver
    app.run()