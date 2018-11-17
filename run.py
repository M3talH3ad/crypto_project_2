from flaskblog import app

if __name__ == '__main__':
    context = ('localhost.crt', 'localhost.key')
    app.run(host='localhost', port=8000, ssl_context=context, threaded=True, debug=True)