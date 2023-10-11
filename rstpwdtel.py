# RSTPWDTEL - Reset Password by Telephone Number
#
# Searches Active Directory for user with specified telephone number and
# resets password with random string conforming to standards
#
# SriniG 10Oct2023

import sys, random
from datetime import datetime
from pyad import aduser, adquery

# IMPORTANT: Ensure AD domain is set correctly here
BASE_DN = 'CN = users, DC = example, DC = com'

# Generate new Password per standards
def gen_pass(pwd_len = 8):
    pwd, allowed = '', []
    allowed.append('abcdefghijkmnopqrstuvwxyz')  # l skipped looks like 1
    allowed.append('ABCDEFGHIJKLMNOPQRTUVWXYZ')  # S skipped looks like 5
    allowed.append('123456789')                  # 0 skipped looks like O
    allowed.append('!@#$%&*+=?')

    random.seed(int(datetime.now().timestamp()))
    for i in range(pwd_len):
        pwd += allowed[i%4][random.randrange(len(allowed[i%4]))]
    return(pwd)

# Get Phone number and password (optional) from command line
arg_len = len(sys.argv)
if arg_len not in (2,3):
    print('Usage: rstpwdtel <telephone_number> <new_password>')
    sys.exit(1)
phone_number = sys.argv[1]
new_pwd = gen_pass() if arg_len == 2 else sys.argv[2]

# Fetch user from Active Directory
q = adquery.ADQuery()
q.execute_query(
    attributes = ['distinguishedName', 'cn'],
    where_clause = f"telephoneNumber = '{phone_number}'",
    base_dn = BASE_DN
    )
result = next(q.get_results())
cn, dn = result['cn'], result['distinguishedName']

# Change Password
aduser.ADUser.from_dn(dn).set_password(new_pwd)
print(f'Changed password for {cn} to {new_pwd}')
