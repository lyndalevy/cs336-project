# test_xss.py — XSS: unsanitized request param rendered into HTML
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q")                        # SOURCE
    template = f"<h1>Results for: {query}</h1>"
    return render_template_string(template)              # SINK — XSS!
