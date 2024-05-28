from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import form, BooleanField, StringField,validators,PasswordField, SubmitField
from wtforms.validators import DataRequired, length, Email, Regexp, EqualTo ,Length
from database import  get_table,insert_products,insert_sales,total_sales,profits, \
    day_sales,profits_day,check_email,register_user,check_logins,total_profit,d_profit,\
        cumulative_sales,total_day_sales,display_product,edit_product,delete_product, profits
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate 

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql://postgres:123456789@localhost/inventory_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
app.app_context().push()
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view='login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db) 
# create a route to homepage
@app.route('/')
def home():
    return render_template('index.html')



class User(db.Model, UserMixin):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return self.id
    


    
class Product(db.Model):
    __tablename__='products'
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(160), nullable=False)
    buying_price = db.Column(db.Numeric(10,2), nullable=False)
    selling_price = db.Column(db.Numeric(10,2), nullable=False)
    stock_quantity = db.Column(db.Numeric(10,2), nullable=False)
    sales = db.relationship('Sale', backref='Product')
    


        

class Sale(db.Model):
    __tablename__='sales'
    id = db.Column(db.Integer, primary_key=True)
    pid = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Numeric(10,2), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

def __repr__(self):
    return(f'sales {self.pid} {self.created_at}')
class RegistrationForm(FlaskForm):
 username = StringField('username', validators=[DataRequired(), Length(min=3 , max=30)],render_kw={'placeholder':'Enter Username'})
 email = StringField('Email Address,', validators=[DataRequired(), Email()],render_kw={'placeholder':'Enter Email'})
 password = PasswordField('New Password', validators=[DataRequired(), Regexp("^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,32}$")], render_kw={'placeholder': 'Enter Password'}) 
 confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={'placeholder':'Confirm Password'})
 submit= SubmitField('Sign Up')


 @login_manager.user_loader # this decorator registers a function that load a user from the user id
 def load_user(user_id):
     return User.query.get(int(user_id))
 

@app.route("/register",methods=['POST','GET'])
def register():
    if current_user.is_authenticated: # if user is already logged in
        return redirect(url_for('home'))
    form = RegistrationForm() # create an instance of the RegistrationForm class
    if form.validate_on_submit(): # if the form is submitted and validated
       hash_password = bcrypt.generate_password_hash(form.password.data).decode ('utf-8') # hash the password
       user = User(name=form.username.data, email=form.email.data, password=hash_password)
       db.session.add(user) # add the user to the database
       db.session.commit() # commit the changes to the database
       flash(f'is registred successfully for {form.username.data}','success')
       return redirect(url_for('login'))
    return render_template("register.html", form = form)

class LoginForm(FlaskForm):
 email = StringField('Email Address,', validators=[DataRequired(), Email()],render_kw={'placeholder':'Enter Email'})
 password = PasswordField('New Password', validators=[DataRequired()], render_kw={'placeholder': 'Enter Password'}) 
 remember = BooleanField('Remember Me')
 submit = SubmitField('Login')

@app.route("/login",methods=['POST','GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first() # check if the email exists in the database
        if user and bcrypt.check_password_hash(user.password, form.password.data): # check if the password is correct
            login_user(user, remember=form.remember.data) # login the user
            next_page = request.args.get('next')
            flash(f'access granted, welcome ',"success")
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('access denied try again',"danger")
    return render_template("login.html" , form = form)


@app.route("/logout")
def logout():
    logout_user()
    flash('You have been successfully logged out', 'success')
    return redirect(url_for('home'))


@app.route('/products')
@login_required
def products():
    all_data = Product.query.all()
    print(all_data)
    return render_template('products.html',prods=all_data)

@app.route('/add_products',methods=['POST'])
@login_required
def add_products():
    if request.method == 'POST':
        pname =request.form["product_name"]
        bprice =request.form["buying_price"]
        sprice =request.form["selling_price"]
        squantity =request.form["stock_quantity"]
        new_products = Product(product_name = pname, buying_price = bprice,selling_price = sprice,stock_quantity = squantity)
        db.session.add(new_products)
        db.session.commit()
        flash(f'{pname} inserted successfully','success')
        return redirect(url_for('products'))

@app.route('/update', methods=['POST', 'GET'])
@login_required
def update():
    if request.method == 'POST':
        my_data = Product.query.get(request.form.get('id'))
        my_data.product_name = request.form['product_name']
        my_data.buying_price = request.form['buying_price']
        my_data.selling_price = request.form['selling_price']
        my_data.stock_quantity = request.form['stock_quantity']
        db.session.commit()
        flash(f'Product Updated Successfully for {my_data.product_name}', 'success')
        return redirect(url_for('products'))

@app.route('/delete/<id>/', methods=['POST', 'GET'])
@login_required
def delete(id):
        my_data = Product.query.get(id)
        db.session.delete(my_data)
        db.session.commit()
        flash(f'Product Deleted Successfully for {my_data.product_name}', 'success')
        return redirect(url_for('products'))

# creating a route for sales
@app.route('/sales')
@login_required
def sales():
        sales=Sale.query.all()
        products = Product.query.all()
        return render_template('sales.html',sales=sales,products=products)

# route for making sales
@app.route('/make_sale', methods=['POST'])
@login_required

def make_sale():
    try:
        pid = int(request.form.get('pid'))
        quantity=int(request.form['quantity'])
        product = Product.query.get(pid)
        if not product: # checking if the product exists
            flash('Invalid Product ID','danger') # if the product does not exist
            return redirect(url_for('sales'))
        stock = product.stock_quantity # getting the stock quantity
        if quantity<=0 or quantity>stock: # checking if the quantity is valid
            flash('Invalid Quantity','danger')
            return redirect(url_for('sales'))
        
        values = (pid,quantity) # values to be inserted into the sales table
        # product.stock_quantity -= quantity # updating tn
        insert_sales(values) # inserting the values into the sales table
        # insert_sales((2,2)) # inserting the values intohe stock quantity
        # db.session.commit() # committing the transactio the sales table

        flash(f'Sales made successfully for {quantity},{product.product_name}', 'success')
    
    except ValueError: # if the quantity is not an integer
        flash('Invalid quantity', 'danger')
    except Exception as e: # if there is an error
        flash(f'Failed to make a sale: {str(e)}', 'error')
    
    return redirect(url_for('sales'))

@app.route('/dashboard')
@login_required
def dashboard():

    
    pro_fits=profits()
    pro=[]
    fits=[]
    for i in pro_fits:
        pro.append(str(i[0]))
        fits.append(float(i[1]))
    # print(sales)
    sales = total_sales()
    names = []
    values = []
    for i in sales:
        # print(i)
        names.append(str(i[0]))
        values.append(float(i[1]))

    profit_per_day=total_profit()
    day_profit= d_profit()
    sales=total_sales()
    all_sales=cumulative_sales()
    all_day_sales=total_day_sales()



    # route to display sales per day
    d_sales = day_sales()
    sales_day = []
    s_day = []
    for i in d_sales:
        sales_day.append(str(i[0]))
        s_day.append(float(i[1]))

    # route to display profits per day
    profit = profits_day()
    pros = []
    fit = []
    for i in profit:
        pros.append(str(i[0]))
        fit.append(float(i[1]))
    return render_template('dashboard.html',sales=sales,names=names,values=values,pro=pro,
                           fits=fits,sales_day=sales_day,s_day=s_day,pros=pros,fit=fit,profit_per_day=profit_per_day,day_profit=day_profit,all_sales=all_sales,all_day_sales=all_day_sales)

@app.route('/contact')
@login_required
def contact():
        return render_template('contact.html')


    

db.create_all()
if __name__=='__main__':
    app.run(debug=True)

#  with app.app_context():
    
