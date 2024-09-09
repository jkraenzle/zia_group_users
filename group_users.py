# Python script for Zscaler Internet Access v6.2
# This script is designed to place a set of users defined by a regular expression match into an existing group.
# Optionally, the script can remove any users that currently exist in the group.

# The script requires installation of the Python requests library in the Python installation.
# This can be done using the command:
# pip install requests

# To execute the script, use the command:
# python group_users.py --cloud <Zscaler Cloud> --api_key <Zscaler API Key> --username <user@domain> [--password <>] --group_name <Existing User Group>
#     --action <test, add or overwrite> --user_regex <"regular expression match"> [--user_field email] [--ssl_verify <True|False>]
#
# The password argument is optional and will be requested during the script if not entered in the command line
# The user_field argument defaults to 'email'

import argparse
import getpass
import time
import requests
import json
import re

def api_request(session, action, url, json=None, ssl_verify=False):

	try:

		headers = {
			'Content-Type': 'application/json',
			'Cache-Control': 'no-cache',
			'User-Agent': 'Zscaler Internet Access (ZIA) Python Script to Group Existing Users'
		}


		if session == None:
			s = requests.Session()
		else:
			s = session
		
		requests.packages.urllib3.disable_warnings()
		if action == 'POST':
			if json != None:
				response = s.post(url, json=json, headers=headers, verify=ssl_verify)
			else:
				response = s.post(url, headers=headers, verify=ssl_verify)
		elif action == 'GET':
			response = s.get(url, headers=headers, verify=ssl_verify)
		elif action == "PUT":
			if json != None:
				response = s.put(url, json=json, headers=headers, verify=ssl_verify)
			else:
				response = s.put(url, json=json, headers=headers, verify=ssl_verify)
		elif action == 'DELETE':
			response = s.delete(url, headers=headers, verify=ssl_verify)
		response.raise_for_status()

		return s, response

	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None

def obfuscate_api_key(seed):

	try:
		now = str(int(time.time() * 1000))
		n = now[-6:]
		r = str(int(n) >> 1).zfill(6)

		key = ''
		for i in range(0, len(str(n)), 1):
			key += seed[int(str(n)[i])]
		for j in range(0, len(str(r)), 1):
			key += seed[int(str(r)[j]) + 2]

		return {'timestamp': now, 'key': key}

	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None

def authenticate(cloud=None, username=None, password=None, api_key=None, ssl_verify=False):

	try:

		url = f"https://zsapi.{cloud}.net/api/v1/authenticatedSession"
		api_obf = obfuscate_api_key(api_key)

		json = {
			'username': username,
			'password': password,
			'apiKey': api_obf['key'],
			'timestamp': api_obf['timestamp']
		}

		session, response = api_request(None, 'POST', url, json=json, ssl_verify=ssl_verify)
		response.raise_for_status()
		return session	
	
	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None


def get_groups(session, cloud, ssl_verify=False):

	try:
		url = f"http://zsapi.{cloud}.net/api/v1/groups"

		session, response = api_request(session, 'GET', url, ssl_verify=ssl_verify)
		response.raise_for_status()

		groups = json.loads(response.content)
		return groups

	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None

def get_users(session, cloud, ssl_verify=False):
	try:
		url = f"http://zsapi.{cloud}.net/api/v1/users?pageSize=10000"
		
		session, response = api_request(session, "GET", url, ssl_verify=ssl_verify)

		users = json.loads(response.content)
		return users
	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None

def add_user_to_group (session, cloud, user, group, ssl_verify=False):

	try:
		url = f"http://zsapi.{cloud}.net/api/v1/users/{user['id']}"
		user['groups'].append(group)

		session, response = api_request(session, "PUT", url, user, ssl_verify=ssl_verify)

		return

	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None


def remove_user_from_group (session, cloud, user, group, ssl_verify=False):

	try:
		url = f"http://zsapi.{cloud}.net/api/v1/users/{user['id']}"


		pos = 0
		for user_group in user['groups']:
			if user_group['id'] == group['id']:
				user['groups'].pop(pos)
				break
			pos += 1

		if len(user['groups']) == 0:
			print(f"Unable to remove user {user['name']} from group {group['name']}, as user is only assigned to this group.")
			print(f"Please first add user to another group before attempting to overwrite and remove them from their currently assigned group.")

		session, response = api_request(session, "PUT", url, user, ssl_verify=ssl_verify)
		
		return
	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None

def activate(session, cloud, ssl_verify=False):

	try:
		url = f"https://zsapi.{cloud}.net/api/v1/status/activate"

		session, response = api_request(session, "POST", url, {"status":"ACTIVE"}, ssl_verify=ssl_verify)

		return

	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None

	return

def logout(session, cloud, ssl_verify=False):

	try:
		url = f"https://zsapi.{cloud}.net/api/v1/authenticatedSession"
		
		session, response = api_request(session, 'DELETE', url, ssl_verify=ssl_verify)

		return 

	except requests.exceptions.RequestException as e:
		raise SystemExit(e) from None
	
		
def main ():

	print("Starting script to group users")
	parser = argparse.ArgumentParser(description="Script to group existing users")
	parser.add_argument('--cloud', help='ZIA Cloud (e.g. zscloud, zscalerone) for tenant', required=True)
	parser.add_argument('--username', help='ZIA admin user with privileges for User Management', required=True)
	parser.add_argument('--password', help='Password for Zscaler admin user', required=False)
	parser.add_argument('--api_key', help='API Key for associated tenant', required=True)
	parser.add_argument('--action', help='add: place users in existing group; overwrite: remove existing users and place specified users into group; test: print expected results', required=True)
	parser.add_argument('--group_name', help='Existing ZIA user group', required=True)
	parser.add_argument('--user_regex', help='Match pattern for users', required=True)
	parser.add_argument('--user_field', help='Field on which to match regular expression', default='email', required=False)
	parser.add_argument('--ssl_verify', help='Optionally, whether API verifies certificate', default=False, required=False)
	args = parser.parse_args()

	print("Step 1 of 5: Validating script arguments")
	zclouds = ['zscaler', 'zscloud', 'zscalerone', 'zscalertwo', 'zscalerthree', 'zsbeta']
	if args.cloud not in zclouds:
		print(f"Cloud {args.cloud} is not a known Zscaler Internet Access cloud.")
		print(f"Known values are one of {','.join(zclouds)}")
		return

	if args.action == 'add':
		pass # Add users that are found to existing Group
	elif args.action == 'overwrite':
		pass # Set users that are found in existing Group
	elif args.action == 'test':
		pass # Testing impact
	else:
		print(f"Action {args.action} is not an option.")
		print("Please re-run script with actions 'add' or 'overwrite'.")
		print("Exiting ...")
		return

	if args.password == "" or args.password == None:
		print(f"Please provide password for username {args.username} on {args.cloud}")
		password = getpass.getpass()
	else:
		password = args.password

	print("Step 2 of 5: Authenticating to Zscaler Internet Access (ZIA)")
	session = authenticate(cloud=args.cloud, username=args.username, password=password, api_key = args.api_key, ssl_verify=args.ssl_verify)

	print(f"Step 3 of 5: Finding target group '{args.group_name}' from ZIA API")
	groups = get_groups(session, args.cloud, args.ssl_verify)

	target_group = None
	for group in groups:
		if args.group_name == group['name']:
			target_group = group
			break

	if target_group == None:
		print(f"Script requires an existing group. Group '{args.group_name}' does not exist.")
		logout(session, args.cloud, args.ssl_verify)
		print("Exiting")
		return
	else:
		print(f"Found existing group '{args.group_name}'.")

	print("Step 4 of 5: Pulling existing users and associated groups from ZIA API")
	users = get_users(session, args.cloud, args.ssl_verify)

	print("Step 5 of 5: Updating/reporting group information for users")
	# Loop over users
	# If either action, user matches regex, user is in group, do nothing
	# If either action, user matches regex, user is not in group, then add
	# If action overwrite, user does not match regex, user is in group, then remove
	users_to_add = []
	users_to_remove = []
	for user in users:
		try:
			if args.user_field in ["email"]:
				match = re.search(args.user_regex, user[args.user_field])
			else:
				if args.user_field in user:
					if "name" in user[args.user_field]:
						match = re.search(args.user_regex, user[args.user_field]["name"])
					else:
						print(f"Error when trying to access '{args.user_field}' for '{user}'")
						continue
				else:
					print(f"Field '{args.user_field}' is not defined for '{user}'")
					continue

			found = False
			for user_group in user['groups']:
				if user_group['name'] == args.group_name:
					found = True

			if match != None and found == False:
				users_to_add.append(user)
			if (args.action == 'overwrite' or args.action == 'test') and match == None and found == True:
				users_to_remove.append(user)

		except Exception as e:
			print(f"Exception '{e}' when attempting to apply regular expression '{args.user_regex}'")
			print("Regular expression match using Python command re.search(user_regex, user_field) failed")
			print("Exiting")

	if args.action == 'test':
		print(f"")
		print(f"***** Test Results *****")
		print(f"")
		print(f"There are {len(users_to_add)} users to add:")
		for user_to_add in users_to_add:
			print(f"* {user_to_add['name']} - {user_to_add['email']}")
		print(f"")
		print(f"There are {len(users_to_remove)} users to remove for action 'overwrite':")
		for user_to_remove in users_to_remove:
			print(f"* {user_to_remove['name']} - {user_to_remove['email']}")
		print(f"**********")
		return

	print(f"\tA total of {len(users_to_add)} user(s) will be added to group '{args.group_name}'")
	for user_to_add in users_to_add:
		print(f"\t\tAdding '{user_to_add['name']}' to '{target_group['name']}'")
		add_user_to_group(session, args.cloud, user_to_add, target_group, args.ssl_verify)
		time.sleep(0.5)

	if args.action == 'overwrite':
		print(f"\tA total of {len(users_to_remove)} users(s) will be removed from the groups.")
		for user_to_remove in users_to_remove:
			print(f"\t\tRemoving '{user_to_remove['name']}' from '{target_group['name']}'")
			remove_user_from_group(session, args.cloud, user_to_remove, target_group, args.ssl_verify)
	
	activate(session, args.cloud, args.ssl_verify)
	logout(session, args.cloud, args.ssl_verify)

	return

if __name__ == "__main__":
	main()
