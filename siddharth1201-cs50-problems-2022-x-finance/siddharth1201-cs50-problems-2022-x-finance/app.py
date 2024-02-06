import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    table_data = {}
    table_data = db.execute("SELECT Symbol,Name,SUM(Share) AS Share,Price,SUM(Total) AS Total FROM stocks WHERE id = ? GROUP BY Symbol",user_id)
    grand_total = 0
    for i in range(0, len(table_data)):
        Symbol = table_data[i]['Symbol']
        table_data[i]['Price'] = lookup(Symbol)["price"]
        table_data[i]['Total'] = table_data[i]['Price']*table_data[i]['Share']
        grand_total = grand_total + table_data[i]['Total']
        table_data[i]['Total'] = usd(table_data[i]['Total'])
        table_data[i]['Price'] = usd(table_data[i]['Price'])
    cash = db.execute("SELECT cash FROM users WHERE id = ?",user_id)[0]["cash"]
    return render_template("index.html", table_data=table_data, cash=usd(cash), grand_total=usd(grand_total+cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")
        symbol_data = {}
        shares = int(request.form.get("shares"))
        symbol_data=lookup(symbol)

        if (not request.form.get("symbol")) or (not request.form.get("shares")):
            return apology("must provide stock symbol and number of shares")

        if symbol_data == None:
            return apology("Invalid Symbol")

        if shares <= 0:
            return apology("Share Not allowed")


        total_price= shares*symbol_data['price']



        user_id=session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id=?",user_id)[0]["cash"]
        if cash>=total_price:
            stock_symbol = symbol_data['symbol']
            stock_name = symbol_data['name']
            stock_price= symbol_data['price']
            now = datetime.now()
            time_now = now.strftime("%H:%M:%S")
            left_cash = cash - total_price
            db.execute("INSERT INTO stocks (id,Symbol,Name,Share,Price,Total,timestamp) VALUES (?,?,?,?,?,?,?)",user_id,stock_symbol,stock_name,shares,stock_price,total_price,time_now)
            db.execute("UPDATE users SET cash = ? WHERE id = ?",left_cash,user_id)
            return redirect("/")


        else:
            return apology("Insufficient balance")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id=session["user_id"]
    stocks_db = db.execute("SELECT * FROM stocks WHERE id = ?",user_id)
    return render_template("history.html", stocks=stocks_db)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote_data = {}
        quote_data=lookup(symbol)
        if quote_data == None:
            return apology("Invalid Symbol")
        quote_data['price'] = usd(quote_data['price'])
        return render_template("quoted.html",quote_data=quote_data)


    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Must provide Username",400)

        if not request.form.get("password"):
            return apology("Must provide password",400)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Re-enter password.")

        name = request.form.get("username")
        password = request.form.get("password")

        check = db.execute("SELECT username FROM users WHERE username=?", name)
        if len(check) > 0:
            return apology("username not available", 400)

        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username,hash) VALUES(?,?)",name,hashed_password)
    return redirect("/")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method=="GET" :
        owned= db.execute("SELECT Symbol,SUM(Share) FROM stocks WHERE id = ? GROUP BY Symbol",session["user_id"])
        return render_template("sell.html",owned=owned)

    if request.method=="POST":
        symbol = request.form.get("symbol")
        symbol_data = {}
        shares = int(request.form.get("shares"))
        symbol_data=lookup(symbol)
        if symbol_data == None:
            return apology("Invalid Symbol")

        if shares < 0:
            return apology("Share Not allowed")



        total_price= shares*symbol_data['price']
        symbol_data['price'] = usd(symbol_data['price'])


        user_id=session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id=?",user_id)[0]["cash"]
        user_shares = db.execute("SELECT SUM(Share) FROM stocks WHERE id =? AND symbol=? GROUP BY Symbol",user_id,symbol)[0]['SUM(Share)']
        print(user_shares)
        if shares>=user_shares:
            return apology("Do not have enough shares.")
        stock_symbol = symbol_data['symbol']
        stock_name = symbol_data['name']
        stock_price= symbol_data['price']
        now = datetime.now()
        time_now = now.strftime("%H:%M:%S")
        db.execute("INSERT INTO stocks (id,Symbol,Name,Share,Price,Total,timestamp) VALUES (?,?,?,?,?,?,?)",user_id,stock_symbol,stock_name,(-1)*shares,stock_price,total_price,time_now)

        left_cash = cash + total_price
        db.execute("UPDATE users SET cash = ? WHERE id = ?",left_cash,user_id)
        return redirect("/")

@app.route("/password",methods=["GET","POST"])
@login_required
def password():
    if request.method == "GET":
        return render_template("password.html")

    if request.method == "POST":
        old_password=request.form.get("old_password")
        user_id = session["user_id"]

        old_hash_1=db.execute("SELECT hash FROM users WHERE id=?",user_id)[0]['hash']
        print(old_hash_1)
        if not check_password_hash(old_hash_1,old_password):
            return apology("incorrect password")

        if request.form.get("new_password") == request.form.get("confirm_password"):
            new_hash=generate_password_hash(request.form.get("new_password"))
            db.execute("UPDATE users SET hash=? WHERE id=?",new_hash,user_id)
            return redirect("/logout")



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
