import numpy as np
import pandas as pd
import string
def generate_random_password(length=12):
    char_pool = string.ascii_letters + string.digits + string.punctuation
    password_array = np.random.choice(list(char_pool), size=length)
    password_series = pd.Series(password_array)
    return ''.join(password_series)
n=int(input("how many digit password want to be excuted:"))
password = generate_random_password(n)
print("Random Password:", password)
