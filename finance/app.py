import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    # get the values from the sql database that are needed
    list_stock = db.execute("SELECT symbol, shares FROM purchases WHERE purchaser_id=?", session['user_id'])
    list_user = db.execute("SELECT cash FROM users WHERE id=?", session['user_id'])
    cash = list_user[0]['cash']
    # get new values of stock
    stockval_new = []
    totalval_new = []
    cash_in_stocks = 0
    length = len(list_stock)
    # Loop to get needed lists and values
    for i in range(length):
        stockval_new.append(lookup(list_stock[i]['symbol'])['price'])
        totalval_new.append(stockval_new[i] * list_stock[i]['shares'])
        cash_in_stocks += totalval_new[i]
    # Turn everything into usd now
    stockval_newusd = []
    totalval_newusd = []
    cashusd = usd(cash)

    for i in range(length):
        stockval_newusd.append(usd(stockval_new[i]))
        totalval_newusd.append(usd(totalval_new[i]))

    # Total cash in stocks
    grand_total = usd(list_user[0]['cash'] + cash_in_stocks)
    return render_template("index.html", length = length, list_stock = list_stock, cash = cashusd, stockval_new = stockval_newusd, totalval_new = totalval_newusd, grand_total = grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        #Check if there are inputs
        if not request.form.get("symbol"):
            return apology("please enter the stock symbol", 400)
        if not request.form.get("shares"):
            return apology("please enter the number of shares you would like to buy", 400)
        # This only works if the input shares is a number as a string
        if request.form.get("shares").isalpha() > 0:
            return apology("invalid number of sharess", 400)
        if (request.form.get("shares").count("/")) >= 1 or (request.form.get("shares").count(".")) >= 1:
            return apology("please enter a integer", 400)
        # if not isinstance(int(request.form.get("shares")), int):
        #    return apology("invalid number of shares", 400)

        #check if inputs are valid
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)
        if quote == None:
            return apology("invalid stock symbol", 400)
        if int(shares) < 1:
            return apology("invalid number of stocks", 400)

        shares = int(shares)
        #check balance and prices
        shares_price = quote['price'] * int(shares)
        user_cash = db.execute("SELECT cash FROM users WHERE id=?", session['user_id'])
        balance = user_cash[0]['cash']
        if shares_price > balance:
            return apology("insuficient balance to make this transaction", 400)

        #Created a table in sqlite3 using SQL code in requirments.txt
        balance = balance - shares_price # New balance after buying
        db.execute("UPDATE users SET cash=? WHERE id=?", balance, session['user_id'])
        # If you bought same stock before join them together
        previous_purchases = db.execute("SELECT * FROM purchases WHERE purchaser_id=? AND symbol=?", session['user_id'], symbol)
        if previous_purchases != False:
            length_purchase=len(previous_purchases)
            total_shares = 0
            for i in range(length_purchase):
                total_shares += previous_purchases[i]['shares']

            total_shares += shares
            shares_price_exist = total_shares * quote['price']
            db.execute("DELETE FROM purchases WHERE purchaser_id=? AND symbol=?", session['user_id'], symbol)
            db.execute("INSERT INTO purchases (purchaser_id, symbol, shares, price_per_share, price_total) VALUES(?, ?, ?, ?, ?)", session['user_id'], quote['symbol'], total_shares, quote['price'], shares_price_exist)
            # Update history table
            db.execute("INSERT INTO history (history_person_id, action, symbol, price, shares) VALUES(?, ?, ?, ?, ?)", session['user_id'], 'BUY', symbol, quote['price'], shares)
            return redirect("/")

        db.execute("INSERT INTO purchases (purchaser_id, symbol, shares, price_per_share, price_total) VALUES(?, ?, ?, ?, ?)", session['user_id'], quote['symbol'], shares, quote['price'], shares_price)
        #redirect to home
        return redirect("/")
    """Buy shares of stock"""
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    history_table = db.execute("SELECT * FROM history WHERE history_person_id=?", session['user_id'])
    action = []
    symbol = []
    price = []
    shares = []
    for row in history_table:
        action.append(row['action'])
        symbol.append(row['symbol'])
        price.append(row['price'])
        shares.append(row['shares'])

    length = len(action)
    """Show history of transactions"""
    return render_template("history.html", action = action, symbol = symbol, price = price, shares = shares, length = length)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if quote == None:
            return apology("invalid stock symbol", 400)
        name = quote['name']
        price = quote['price']
        price = usd(price)
        symbol = quote['symbol']
        return render_template("quoteout.html", name = name, price = price, symbol = symbol)

    """Get stock quote."""
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("please enter username", 400)
        # Check for duplicate username
        usernames_list = db.execute("SELECT username FROM users")
        usernames = []
        for i in range(len(usernames_list)):
            usernames.append(usernames_list[i]['username'])

        if username in usernames:
            return apology("username allready in use", 400)

        passw = request.form.get("password")
        if not passw:
            return apology("please enter password", 400)

        passwcon = request.form.get("confirmation")
        if not passwcon:
            return apology("please enter password confirmation", 400)

        if passw != passwcon:
            return apology("the passwords do not match, please try again.", 400)

        hashedpass = generate_password_hash(passw, method='pbkdf2', salt_length=16)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashedpass)
        print("hey")
        return redirect("/login")

    """Register user"""
    return render_template("register.html")
    #return apology("Unable to register", 403)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol_sell = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if symbol_sell == None:
            return apology("please enter a stock symbol", 400)
        if shares < 1:
            return apology("please enter a valid number of stocks", 400)
        quote = lookup(symbol_sell)
        # Check if values are
        if quote == None:
            return apology("invalid symbol", 400)
        # See if the owner owns enough stocks to sell
        purchases_info = db.execute("SELECT shares FROM purchases WHERE purchaser_id=? AND symbol=?", session['user_id'], symbol_sell)
        shares_owned = purchases_info[0]['shares']
        if shares > shares_owned:
            return apology("you dont own enough stocks at that company", 400)

        # If he owns enough stocks he can now sell the stock.
        # This part add the money to his users data
        price_to_sell = quote['price']
        balance_to_add = shares * price_to_sell
        user_info = db.execute("SELECT cash FROM users WHERE id=?", session['user_id'])
        current_balance = user_info[0]['cash']
        new_balance = current_balance + balance_to_add
        db.execute("UPDATE users SET cash=? WHERE id=?", new_balance, session['user_id'])
        # calculate the amount of shares the owner now has and change the purchases table accordingly
        shares_new = shares_owned - shares
        if shares_new == 0:
            db.execute("DELETE FROM purchases WHERE purchaser_id=? AND symbol=?", session['user_id'], symbol_sell)
            return redirect("/")
        # Update history table
        db.execute("INSERT INTO history (history_person_id, action, symbol, price, shares) VALUES(?, ?, ?, ?, ?)", session['user_id'], 'SELL', symbol_sell, quote['price'], shares)
        # if new amount of shares is not 0 update the existing table
        db.execute("UPDATE purchases SET shares=? WHERE purchaser_id=? AND symbol=?", shares_new, session['user_id'], symbol_sell)
        # return to home
        return redirect("/")

    totalsymbol=[] # list of all symbols for stocks the user owns
    purchaser_table = db.execute("SELECT * FROM purchases WHERE purchaser_id=?", session['user_id'])
    for i in range(len(purchaser_table)):
        totalsymbol.append(purchaser_table[i]['symbol'])

    """Sell shares of stock"""
    return render_template("sell.html", totalsymbol=totalsymbol)

@app.route("/changepass", methods=["GET", "POST"])
@login_required
def change_pass():
    if request.method == "POST":
        # Get password hashes and new password for comparison
        current_password = request.form.get("current_password") # Requested
        print(f"{current_password}")
        new_password = request.form.get("new_password")
        user_pass = db.execute("SELECT * FROM users WHERE id=?", session['user_id'])
        if not check_password_hash(user_pass[0]['hash'], current_password):
            return apology("your current password does not match, please try again", 400)

        if len(new_password) < 1:
            return apology("please enter a new password", 400)
        # Update users table with new hash and then logout the user so he can log in again
        new_passwordhash = generate_password_hash(new_password, method='pbkdf2', salt_length=16)
        db.execute("UPDATE users SET hash=? WHERE id=?", new_passwordhash, session['user_id'])
        # Forget any user_id
        session.clear()
        # Redirect user to login form
        return redirect("/")

    return render_template("changepass.html")
