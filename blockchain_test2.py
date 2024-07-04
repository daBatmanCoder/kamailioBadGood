import http.server
import socketserver
import json
import random
import string
from xmlrpc.client import boolean
from jsonrpcserver import Error, Result, dispatch, method, serve, Success
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from http.server import BaseHTTPRequestHandler, HTTPServer
from web3 import Web3
import socketserver
import json
import requests
import threading
import time
import base64
from eth_account.messages import encode_defunct
from eth_account import Account
from Crypto.Hash import keccak
import re


# Load the configuration file
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

amoy_url = config['amoy_url']
w3 = Web3(Web3.HTTPProvider(amoy_url))

contract_address_of_ens = config['contract_address_of_ens']
contract_abi_of_ens = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"owner","type":"address"},{"indexed":True,"internalType":"address","name":"operator","type":"address"},{"indexed":False,"internalType":"bool","name":"approved","type":"bool"}],"name":"ApprovalForAll","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":True,"internalType":"bytes32","name":"label","type":"bytes32"},{"indexed":False,"internalType":"address","name":"owner","type":"address"}],"name":"NewOwner","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"address","name":"resolver","type":"address"}],"name":"NewResolver","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"NewTTL","type":"event"},{"inputs":[{"internalType":"address","name":"operator","type":"address"},{"internalType":"bool","name":"approved","type":"bool"}],"name":"setApprovalForAll","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"setOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"resolver","type":"address"}],"name":"setResolver","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"bytes32","name":"label","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"setSubnodeOwner","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"bytes32","name":"label","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setSubnodeRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setTTL","outputs":[],"stateMutability":"nonpayable","type":"function"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"address","name":"owner","type":"address"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"operator","type":"address"}],"name":"isApprovedForAll","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"recordExists","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"resolver","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"ttl","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"}]

contract_address_of_sp = config['contract_address_of_sp']
contract_abi_of_sp = [{"inputs": [{"internalType": "address", "name": "_admin", "type": "address"}], "name": "addAdmin", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "string", "name": "gsm_number", "type": "string"}, {"internalType": "string", "name": "gsm_metadata", "type": "string"}, {"internalType": "uint256", "name": "IPSForNumber", "type": "uint256"}], "name": "addGSM", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "string", "name": "ip", "type": "string"}], "name": "addNewIPRoute", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "uint256", "name": "_setupFee", "type": "uint256"}, {"internalType": "uint256", "name": "_monthlyFee", "type": "uint256"}, {"internalType": "string", "name": "_metaData", "type": "string"}], "name": "addProduct", "outputs": [], "stateMutability": "payable", "type": "function"}, {"inputs": [{"internalType": "uint256", "name": "_commitmentDeposit", "type": "uint256"}, {"internalType": "uint256", "name": "_productID", "type": "uint256"}], "name": "createSubscription", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "uint32", "name": "_levels", "type": "uint32"}, {"internalType": "contract IHasher", "name": "_hasher", "type": "address"}, {"internalType": "contract IVerifier", "name": "_verifier", "type": "address"}, {"internalType": "contract IMetadata", "name": "_metadataContract", "type": "address"}, {"internalType": "contract IServiceProviders", "name": "_spsContract", "type": "address"}, {"internalType": "contract IPalo", "name": "_fundsContract", "type": "address"}, {"internalType": "contract IAyala", "name": "_ayalaContract", "type": "address"}, {"internalType": "bytes32", "name": "_serviceProviderNode", "type": "bytes32"}, {"internalType": "string", "name": "_metaData", "type": "string"}, {"internalType": "string", "name": "_serviceProviderDomain", "type": "string"}], "stateMutability": "payable", "type": "constructor"}, {"anonymous": False, "inputs": [{"indexed": True, "internalType": "address", "name": "admin", "type": "address"}, {"indexed": False, "internalType": "bool", "name": "isAdded", "type": "bool"}], "name": "AdminChanged", "type": "event"}, {"inputs": [{"internalType": "uint256[2]", "name": "_proof_a", "type": "uint256[2]"}, {"internalType": "uint256[2][2]", "name": "_proof_b", "type": "uint256[2][2]"}, {"internalType": "uint256[2]", "name": "_proof_c", "type": "uint256[2]"}, {"internalType": "uint256", "name": "_nullifierHash", "type": "uint256"}, {"internalType": "uint256", "name": "_root", "type": "uint256"}, {"internalType": "uint256", "name": "_productID", "type": "uint256"}], "name": "extendSubscription", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "string", "name": "gsm_number", "type": "string"}, {"internalType": "address", "name": "user_address", "type": "address"}], "name": "listGSM", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "address", "name": "_admin", "type": "address"}], "name": "removeAdmin", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"anonymous": False, "inputs": [{"indexed": False, "internalType": "address", "name": "subscriptionContract", "type": "address"}], "name": "showAddress", "type": "event"}, {"anonymous": False, "inputs": [{"indexed": False, "internalType": "string", "name": "ens", "type": "string"}], "name": "showENS", "type": "event"}, {"inputs": [{"internalType": "uint256[2]", "name": "_proof_a", "type": "uint256[2]"}, {"internalType": "uint256[2][2]", "name": "_proof_b", "type": "uint256[2][2]"}, {"internalType": "uint256[2]", "name": "_proof_c", "type": "uint256[2]"}, {"internalType": "uint256", "name": "_nullifierHash", "type": "uint256"}, {"internalType": "uint256", "name": "_root", "type": "uint256"}, {"internalType": "string", "name": "ens", "type": "string"}], "name": "startSubscription", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "bytes", "name": "_signature", "type": "bytes"}, {"internalType": "string", "name": "_messageSigned", "type": "string"}, {"internalType": "bytes32", "name": "_ENSNode", "type": "bytes32"}], "name": "updateNewServiceProvider", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"internalType": "address", "name": "", "type": "address"}], "name": "admins", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "uint256", "name": "number", "type": "uint256"}], "name": "getIPsForNumber", "outputs": [{"internalType": "string[]", "name": "", "type": "string[]"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "gsm_number", "type": "string"}], "name": "getIPSFromNumber", "outputs": [{"internalType": "string[]", "name": "", "type": "string[]"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "uint256", "name": "_productID", "type": "uint256"}], "name": "getProductMetaData", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "getServiceProviderDomain", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "getServiceProviderMetadata", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "", "type": "string"}], "name": "GSM", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "", "type": "string"}], "name": "GSMIPS", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "INDEX_OF_METADATA", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "indexOfIP", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "ens", "type": "string"}], "name": "isUserValid", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "pure", "type": "function"}, {"inputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "name": "KamailioIPS", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "OWNER", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "SERVICE_PROVIDER_DOMAIN", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "SERVICE_PROVIDER_NODE", "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "str", "type": "string"}], "name": "stringToUint", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "pure", "type": "function"}]


def get_owner_of_ens(ens):

	ens_contract = w3.eth.contract(address = contract_address_of_ens, abi=contract_abi_of_ens)
	hashed_name = namehash(ens)
	address_of_ens = ens_contract.functions.owner(hashed_name).call()

	return address_of_ens
  

def verify_signature(message, signature):

    w3 = Web3()
    message_encoded = encode_defunct(text=message)

    # Recover the signer from the signature
    try:
        recovered_signer = w3.eth.account.recover_message(message_encoded, signature=signature)
        return recovered_signer

    except Exception as e:
        print(f"An error occurred: {e}")
        return "404"

def keccak256(data):
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def namehash(name):
	name = name.lower()
	if name == '':
		return '0x' + '00' * 32  # Return keccak256 hash of empty string for the root node
	else:
		labels = name.split('.')
		labels.reverse()
		hash = bytes.fromhex('00' * 32)  # Start with hash of empty label
		for label in labels:
			hash = keccak256(hash + keccak256(label.encode('utf-8')))
		return '0x' + hash.hex()


def get_time_from_message(message):
    return message.split(":")[1]

@method
def check_if_user_valid(ens, sign, message_signed)  -> str: 
	# ens is the registerant.
	print("ENS of the caller: " + ens)
      
	if len(sign) < 94:
		bytes_data = base64.b64decode(sign)
		# Convert the bytes to a hexadecimal string (if needed)
		sign = bytes_data.hex()
		print("Hex String:", sign)  

	current_time = int(time.time() * 1000)
	time_from_message = int(get_time_from_message(message_signed))
      
	if current_time - time_from_message > 20000:
		print("time passed already but for now it's okay")
		# return "404"
	
	user_address_from_sign = verify_signature(message_signed, sign)
	print("user address from sign: " + user_address_from_sign)
     
	if ens.isdigit():
		user_address_from_ens = get_gsm_address(ens)
	else:
		user_address_from_ens = get_owner_of_ens(ens)

            
	print("user address from ens: " + user_address_from_ens)

	if user_address_from_ens == "0x0000000000000000000000000000000000000000":
		print("invalid ENS")
		return "404"

	if user_address_from_ens == user_address_from_sign: #and is_user_valid_with_subscription(ens):
            
		print("The user is valid to register or connect!")
		return "200"
	else:
		print("The user is not the owner of the NFT")
		return "404"


def get_gsm_address(gsm_number):

	# Create the contract instance
	contract = w3.eth.contract(address=contract_address_of_sp, abi=contract_abi_of_sp)

	# Make the GET call
	result = contract.functions.GSM(gsm_number).call()

	if result == "":
		return "404"

	return result 

def is_user_valid_with_subscription(ens):
      
	sp_contract = w3.eth.contract(address = contract_address_of_sp, abi=contract_abi_of_sp)
	return sp_contract.functions.isUserValid(ens).call()
      

def get_ens_resolver(ens):
    url = "https://us-central1-arnacon-nl.cloudfunctions.net/server_helper_subdomains"
    payload = { 'domain': ens }
    response = requests.post(url, json=payload)
    response.raise_for_status()  # This will raise an HTTPError if the HTTP request returned an unsuccessful status code
    # print("Response Status:", response.status_code)
    # print("Response Text:", response.text)
    return response.text


@method
def send_notification_voip_invite(ens, calleer):
	# ens is the destination
	# callee is the sender 
	url = "https://us-central1-arnacon-nl.cloudfunctions.net/voip_noti"
	print(ens)
	
	print(calleer)
	payload = { 'ens': ens, 'callee':calleer , 'domain': config['server_name'] }

	response = requests.post(url, json=payload)
	response.raise_for_status()  # This will raise an HTTPError if the HTTP request returned an unsuccessful status code

	return response.status_code # If succesful then 200

def check_if_gsm_allowed_call(user_called, gsm, ip):
	  
	sp_contract = w3.eth.contract(address = contract_address_of_sp, abi=contract_abi_of_sp)
	resultFromBC = sp_contract.functions.getIPSFromNumber(gsm).call()
	print(resultFromBC)
	if len(resultFromBC) == 0:
		return "404"
	
	print("heyhey")
	for i in range(0, len(resultFromBC)):
		if resultFromBC[i] == ip:
			print("The IP is valid and legit")
			send_notification_voip_invite(user_called, gsm)

			return "200"

	return "404" # If not found then return 404


def extract_number(sip_uri):
    # Define a regular expression pattern to find the number after 'sip:' and before '@'
    pattern = r'sip:(\d+)@'
    
    # Search the string for the pattern
    match = re.search(pattern, sip_uri)
    
    # If a match is found, return the number
    if match:
        return match.group(1)
    else:
        return "No valid SIP number found."


def check_if_gsm_alloweded_to_make_outside_call(gsm, ip, signature, data_signed):
	sp_contract = w3.eth.contract(address = contract_address_of_sp, abi=contract_abi_of_sp)
	resultFromBC = sp_contract.functions.getIPSFromNumber(gsm).call()
	print(resultFromBC)
	if len(resultFromBC) == 0:
		return "404"

	print("Passed blockchain")
	if check_if_user_valid(gsm, signature, data_signed) == "404":
		return "404"

	print("Passed sanity check of user")

	random_number = random.randint(0, len(resultFromBC))
	return resultFromBC[random_number]


@method
def send_notification_voip(user_called, signature,data_signed, user_destination):
      
	print(user_called)
	print(user_destination)
      
	after_colon = user_destination.split(':')[1]
      
	if len(signature) < 94:
		bytes_data = base64.b64decode(signature)
		# Convert the bytes to a hexadecimal string (if needed)
		signature = bytes_data.hex()
		# signature = "0x" + signature
		print("Hex String:", signature)
            

    # Now split by the "@" and take the first part
	user_id = after_colon.split('@')[0]
	print(user_id)
	if check_if_user_valid(user_called,signature,data_signed) == "404":
		return "404"
	

	return send_notification_voip_invite(user_called, user_id)	



class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
	def do_POST(self):

		# Extract the function name from the path
		function_name = self.path.strip("/").split("/")[-1]
		print("Function name:", function_name)

		# Read the data from the request

		# Determine the length of the data
		content_length = int(self.headers['Content-Length'])
		# Read the data from the request
		post_data = self.rfile.read(content_length)
		print("Received data:", post_data.decode('utf-8'))

		try:
			pre_json = post_data.decode('utf-8')
			data = json.loads(pre_json)

			user_ens = data['ens']

			if function_name == "send_notification_voip":

				ip_of_server = data['source_ip']
				print("IP of server: " + ip_of_server)

				if data['sign'] != "<null>":

					signature = data['sign']
					data_signed = data['data']
					callee = data['callee']


					if user_ens.startswith("+"):
						response = check_if_gsm_alloweded_to_make_outside_call(user_ens[1:], ip_of_server, signature, data_signed)

					else:
						if user_ens.isnumeric():
							response = check_if_gsm_alloweded_to_make_outside_call(user_ens, ip_of_server, signature, data_signed)
							
						else:
							response = send_notification_voip(user_ens, signature,data_signed, callee)
				else:
					print("Not sign")
					callee = data['callee']

					callee = extract_number(callee)
					
					if user_ens.startswith("+"):
						user_ens = user_ens[1:]

					if callee.startswith("+"):
						print(callee[1:])
						response = check_if_gsm_allowed_call(user_ens, callee[1:], ip_of_server)
					else:
						if callee.isnumeric():
							print(callee)
							response = check_if_gsm_allowed_call(user_ens, callee, ip_of_server)
							

			elif function_name == "check_if_user_valid": # RECENT 29/4/2024 function update
				
				signature = data['sign']
				data_signed = data['data']
				response = check_if_user_valid(user_ens,signature,data_signed)

		except json.JSONDecodeError:
			response = "error"
			print("Received data (raw - error):", post_data.decode('utf-8'))

		print("The response of the python script: " + response)
            
		# if response == "200":
		# Send a response back to the client
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers() 
		self.wfile.write(response.encode('utf-8'))   
	


if __name__ == "__main__":
    # Define the server address and port
    server_address = ('localhost', 5003)

    # Create an HTTP server
    httpd = ThreadedHTTPServer(server_address, SimpleHTTPRequestHandler)

    print("Serving HTTP on localhost port 5003...")
    httpd.serve_forever()
