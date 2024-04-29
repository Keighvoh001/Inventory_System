import psycopg2
# connecting to the database
conn=psycopg2.connect(
    dbname="inventory_system",
    user="postgres",
    password="123456789",
    host= "localhost",
    port=5432
)
# open a cursor to perform database operation
cur=conn.cursor()




# to dispaly products and sales on one table
def get_table(table):
    select=f'select * from {table};'
    cur.execute(select)
    results=cur.fetchall()
    return results
   

# inserting products part 1

def insert_products(values):
    insert= "insert into products(name,buying_price,selling_price,stock_quantity)values(%s,%s,%s,%s);"
    cur.execute(insert,values)
    conn.commit()


# inserting sales

def insert_sales(values):
    insert = "insert into sales(pid,quantity,created_at)values(%s,%s,now());"
    cur.execute(insert,values)
    conn.commit()
# get_table('products')
# get_table('sales')
# sales_values=(2,5) # (pid,quantity)
# insert_sales(sales_values)

# get_table('sales')

# total sales to display every sale
def total_sales():
    total_sales = "select p.product_name, sum(selling_price*quantity) as result from products as p join sales on sales.pid=p.id group by p.product_name;"
    cur.execute(total_sales)
    results=cur.fetchall()
    # print(results)
    return results

# total profit
def profits ():
    total_profits='select p.product_name, sum(((selling_price-buying_price)*quantity))\
        as profit from products as p join sales as s on s.pid=p.id group by p.product_name;'
    cur.execute(total_profits)
    results=cur.fetchall()
    return results

def day_sales():
    d_sales = 'select DATE(created_at) as date_only, sum((selling_price)*quantity) \
        as total_sales from sales as s join products as p on p.id=s.pid group by date_only order by date_only;'
    cur.execute(d_sales)
    result=cur.fetchall()
    return result

# profit per day
def profits_day():
    d_profits='select DATE(created_at) as date_only, sum(selling_price-buying_price) \
        as profits from sales as s join products as p on p.id=s.pid group by date_only order by date_only;'
    cur.execute(d_profits)
    result = cur.fetchall()
    return result
# total profit
def total_profit():
    faida = 'select round(sum(((selling_price-buying_price)*quantity)),2) \
        as profit from products as p join sales as s on s.pid=p.id;'
    cur.execute(faida)
    result= cur.fetchall()
    return result
# profit for today
def d_profit():
    day_profit="SELECT TO_CHAR(CURRENT_DATE, 'YYYY/MM/DD') as date_only,round(sum(selling_price-buying_price),2) as profits from sales \
        as s join products as p on p.id=s.pid group by date_only order by date_only limit 1;"
    cur.execute(day_profit)
    result=cur.fetchall()
    return result

# calculating sales cumulatively
def cumulative_sales():
    c_sales = "select round(sum(selling_price)) as result from products;"
    cur.execute(c_sales)
    results=cur.fetchall()
    # print(results)
    return results
# calculating total sales per day
def total_day_sales():
    t_d_sales = 'select date(created_at) as today_date,round(sum(selling_price),2) as total_sales from products as p join sales \
        as s on s.pid=p.id where date(created_at)=current_date group by today_date;'
    cur.execute(t_d_sales)
    result=cur.fetchall()
    return result

# displaying sales by name of the product

def display_product(a):
    p_name= "select p.name from products as p where id=%s;"
    cur.execute(p_name,(a,))
    result=cur.fetchone()
    return result

# editing a product

def edit_product(values):
    e_product='UPDATE products SET full_name=%s, email=%s, password=%s WHERE id=%s;'
    cur.execute(e_product,(values,))
    conn.commit()

# deleting a products
def delete_product(product_id, cur, conn):
    delete_query = 'DELETE FROM products WHERE id = %s;'
    cur.execute(delete_query, (product_id,))
    # len cur
    row_count = cur.rowcount
    conn.commit()
    return row_count


def register_user(values):
    insert="insert into users(full_name,email,password)values(%s,%s,%s)"
    cur.execute(insert,values)
    conn.commit()

def check_email(email):
    query='select exists(select 1 from users where email=%s)'
    cur.execute(query,(email,))
    exist=cur.fetchone()[0]
    return exist

def check_logins(email,password):
    query='select id,full_name from users where email=%s and password=%s'
    cur.execute(query,(email,password,))
    result=cur.fetchone()
    return result

    










