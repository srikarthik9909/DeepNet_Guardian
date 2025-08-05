from flask import Flask, jsonify, render_template
import os
import json

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def get_data():
    if os.path.exists("output.json"):
        with open("output.json", "r") as f:
            data = json.load(f)
        return jsonify(data)
    else:
        return jsonify({"error": "output.json not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
