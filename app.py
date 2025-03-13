from flask import Flask

app = Flask(__name__)

from routes import check_email

@app.route('/')
def landing_page():
    return "hello, World!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=8000)