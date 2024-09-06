# Overview

This script is designed to place a set of users defined by a regular expression match into an existing group.
Optionally, the script can remove any users that currently exist in the group.

# Prerequisites
The script requires installation of the Python requests library in a Python 3.10 installation.
This can be done using the command:
pip install requests

# Execution
To execute the script, use the command:

```
python group_users.py --cloud <Zscaler Cloud> 
     --username <user@domain> [--password <>] --api_key <Zscaler API Key>
     --group_name <Existing User Group>
     --action <test, add, or overwrite>
     --user_regex <"regular expression match"> [--user_field email]
     [--ssl_verify <True|False>]
```

The password argument is optional and will be requested during the script if not entered in the command line.
The user_field argument defaults to 'email'.

# Limitations

The script is limited in current implementation to tenants with less than 10,000 users. The function get_users would need to be modified to pageinate and iterate over multiple requests to support larger numbers.

# Example Output

> (group_users) jkraenzle@Josephs-MacBook-Pro group_users % python3 group_users.py --cloud zscalertwo --username api@krnzl.com --api_key <> --action test --group_name Test --user_regex Operations --user_field department
>
> Starting script to group users
> Step 1 of 5: Validating script arguments
> Please provide password for username api@krnzl.com on zscalertwo
> Password: 
> Step 2 of 5: Authenticating to Zscaler Internet Access (ZIA)
> Step 3 of 5: Finding target group 'Test' from ZIA API
> Found existing group 'Test'.
> Step 4 of 5: Pulling existing users and associated groups from ZIA API
> Step 5 of 5: Updating/reporting group information for users
> Field 'department' is not defined for '{'id': 108207994, 'name': 'Test User', 'email': 'test@global.krnzl.com', 'groups': [{'id': 40821892, 'name': 'Test'}], 'adminUser': False, 'isNonEditable': False, 'deleted': False}'
> Field 'department' is not defined for '{'id': 108207995, 'name': 'Test User', 'email': 'test@sub.krnzl.com', 'groups': [{'id': 40821892, 'name': 'Test'}], 'adminUser': False, 'isNonEditable': False, 'deleted': False}'
> 
> ***** Test Results *****
> 
> There are 4 users to add:
> * DEFAULT ADMIN - admin@39426176.zscalertwo.net
> * Admin - admin@krnzl.com
> * API Admin - api@krnzl.com
> * Cloud Connectors - cloudconnectors@krnzl.com
> 
> There are 3 users to remove for action 'overwrite':
> * Restricted User - restricted@krnzl.com
> * Test User - test@krnzl.com
> * Unrestricted User - unrestricted@krnzl.com
**********
```
