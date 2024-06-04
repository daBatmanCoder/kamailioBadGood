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

# Load the configuration file
with open('config.json', 'r') as config_file:
    config = json.load(config_file)
    
# with open('ens_abi.json', 'r') as abi_file:
#     contract_abi_of_ens = json.load(abi_file)
    
contract_abi_of_ens = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"owner","type":"address"},{"indexed":True,"internalType":"address","name":"operator","type":"address"},{"indexed":False,"internalType":"bool","name":"approved","type":"bool"}],"name":"ApprovalForAll","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":True,"internalType":"bytes32","name":"label","type":"bytes32"},{"indexed":False,"internalType":"address","name":"owner","type":"address"}],"name":"NewOwner","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"address","name":"resolver","type":"address"}],"name":"NewResolver","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"NewTTL","type":"event"},{"inputs":[{"internalType":"address","name":"operator","type":"address"},{"internalType":"bool","name":"approved","type":"bool"}],"name":"setApprovalForAll","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"setOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"resolver","type":"address"}],"name":"setResolver","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"bytes32","name":"label","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"setSubnodeOwner","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"bytes32","name":"label","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setSubnodeRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setTTL","outputs":[],"stateMutability":"nonpayable","type":"function"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"address","name":"owner","type":"address"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"operator","type":"address"}],"name":"isApprovedForAll","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"recordExists","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"resolver","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"ttl","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"}]


# with open('sp_abi.json', 'r') as abi_files:
#     contract_abi_of_sp = json.load(abi_files)
    
ens_semaphores = {}

amoy_url = config['amoy_url']
w3 = Web3(Web3.HTTPProvider(amoy_url))

contract_address_of_ens = config['contract_address_of_ens']
# contract_abi_of_ens = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"owner","type":"address"},{"indexed":True,"internalType":"address","name":"operator","type":"address"},{"indexed":False,"internalType":"bool","name":"approved","type":"bool"}],"name":"ApprovalForAll","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":True,"internalType":"bytes32","name":"label","type":"bytes32"},{"indexed":False,"internalType":"address","name":"owner","type":"address"}],"name":"NewOwner","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"address","name":"resolver","type":"address"}],"name":"NewResolver","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"NewTTL","type":"event"},{"inputs":[{"internalType":"address","name":"operator","type":"address"},{"internalType":"bool","name":"approved","type":"bool"}],"name":"setApprovalForAll","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"setOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"resolver","type":"address"}],"name":"setResolver","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"bytes32","name":"label","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"setSubnodeOwner","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"bytes32","name":"label","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setSubnodeRecord","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"uint64","name":"ttl","type":"uint64"}],"name":"setTTL","outputs":[],"stateMutability":"nonpayable","type":"function"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"node","type":"bytes32"},{"indexed":False,"internalType":"address","name":"owner","type":"address"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"operator","type":"address"}],"name":"isApprovedForAll","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"recordExists","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"resolver","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"ttl","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"}]

contract_address_of_sp = config['contract_address_of_sp']
contract_abi_of_sp = [
	{
		"inputs": [
			{
				"internalType": "uint32",
				"name": "_levels",
				"type": "uint32"
			},
			{
				"internalType": "contract IHasher",
				"name": "_hasher",
				"type": "address"
			},
			{
				"internalType": "contract IVerifier",
				"name": "_verifier",
				"type": "address"
			},
			{
				"internalType": "contract IMetadata",
				"name": "_metadataContract",
				"type": "address"
			},
			{
				"internalType": "contract IServiceProviders",
				"name": "_spsContract",
				"type": "address"
			},
			{
				"internalType": "contract IPalo",
				"name": "_fundsContract",
				"type": "address"
			},
			{
				"internalType": "contract IAyala",
				"name": "_ayalaContract",
				"type": "address"
			},
			{
				"internalType": "bytes32",
				"name": "_serviceProviderNode",
				"type": "bytes32"
			},
			{
				"internalType": "string",
				"name": "_metaData",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_serviceProviderDomain",
				"type": "string"
			}
		],
		"stateMutability": "payable",
		"type": "constructor"
	},
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": False,
				"internalType": "address",
				"name": "subscriptionContract",
				"type": "address"
			}
		],
		"name": "showAddress",
		"type": "event"
	},
	{
		"inputs": [],
		"name": "INDEX_OF_METADATA",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "SERVICE_PROVIDER_DOMAIN",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "SERVICE_PROVIDER_NODE",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_setupFee",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_monthlyFee",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "_metaData",
				"type": "string"
			}
		],
		"name": "addProduct",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_commitmentDeposit",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_productID",
				"type": "uint256"
			}
		],
		"name": "createSubscription",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[2]",
				"name": "_proof_a",
				"type": "uint256[2]"
			},
			{
				"internalType": "uint256[2][2]",
				"name": "_proof_b",
				"type": "uint256[2][2]"
			},
			{
				"internalType": "uint256[2]",
				"name": "_proof_c",
				"type": "uint256[2]"
			},
			{
				"internalType": "uint256",
				"name": "_nullifierHash",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_root",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_productID",
				"type": "uint256"
			}
		],
		"name": "extendSubscription",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_productID",
				"type": "uint256"
			}
		],
		"name": "getProductMetaData",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getServiceProviderDomain",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getServiceProviderMetadata",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "ens",
				"type": "string"
			}
		],
		"name": "isUserValid",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "pure",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[2]",
				"name": "_proof_a",
				"type": "uint256[2]"
			},
			{
				"internalType": "uint256[2][2]",
				"name": "_proof_b",
				"type": "uint256[2][2]"
			},
			{
				"internalType": "uint256[2]",
				"name": "_proof_c",
				"type": "uint256[2]"
			},
			{
				"internalType": "uint256",
				"name": "_nullifierHash",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "_root",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "ens",
				"type": "string"
			}
		],
		"name": "startSubscription",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes",
				"name": "_signature",
				"type": "bytes"
			},
			{
				"internalType": "string",
				"name": "_messageSigned",
				"type": "string"
			},
			{
				"internalType": "bytes",
				"name": "_ENSNode",
				"type": "bytes"
			}
		],
		"name": "updateNewServiceProvider",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]

def get_owner_of_ens(ens):

	ens_contract = w3.eth.contract(address = contract_address_of_ens, abi=contract_abi_of_ens)
	hashed_name = namehash(ens)
	address_of_ens = ens_contract.functions.owner(hashed_name).call()

	return address_of_ens
  
def generate_username_password():
    # Define the character set for the username and password
    char_set = string.ascii_letters + string.digits  # A-Z, a-z, 0-9

    # Define the length of the username and password
    username_length = random.randint(16, 20)  # Random length between 10 and 16
    password_length = random.randint(20, 24)  # Random length between 12 and 16

    # Generate the username and password
    username = ''.join(random.choice(char_set) for _ in range(username_length))
    password = ''.join(random.choice(char_set) for _ in range(password_length))

    print("Generated username and password: " + username + " " + password)

    #return username + ":" + password
    return f"{username}:{password}" # For now override


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
    if name == '':
        return '0x' + '00' * 32  # Return keccak256 hash of empty string for the root node
    else:
        labels = name.split('.')
        labels.reverse()
        hash = bytes.fromhex('00' * 32)  # Start with hash of empty label
        for label in labels:
            hash = keccak256(hash + keccak256(label.encode('utf-8')))
        return '0x' + hash.hex()


@method
def provide_credentials(ens, sign, call_id)  -> str: 
	# ens is the registerant.
	print("ENS of the caller: " + ens)

	# Need to get from the identity the name of that identity - because when we send to the user the noti we want to send with the calleer.
	# 
	user_address_from_sign = verify_signature(call_id, sign)
	# user_address = get_ens_resolver(ens)
	print("user address from sign: " + user_address_from_sign)
	user_address_from_ens = get_owner_of_ens(ens)

	if user_address_from_ens == user_address_from_sign:
		print("The user is the owner of the ENS")
		return "200"
	else:
		print("The user is not the owner of the NFT")
		return "404"

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
     
	user_address_from_ens = get_owner_of_ens(ens)
	print("user address from ens: " + user_address_from_ens)
      

	if user_address_from_ens == user_address_from_sign: #and is_user_valid_with_subscription(ens):
            
		print("The user is the owner of the ENS")
		return "200"
	else:
		print("The user is not the owner of the NFT")
		return "404"


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
def provide_invite_encrypted_credentials(ens, identity)  -> str: 
    # ens is the registerant.
    print("ENS of the caller: " + ens)
    print("Identity of the caller: " + identity)

    return "hey"


def common_part(url, payload, ens):

    try: 
        response = requests.post(url, json=payload)
        response.raise_for_status()  # This will raise an HTTPError if the HTTP request returned an unsuccessful status code

        print("Response Status:", response.status_code)
        print("Response Text:", response.text)

        if ens not in ens_semaphores:
            ens_semaphores[ens] = threading.Semaphore(0)

        print(f"Thread for {ens} started, trying to acquire semaphore.")
        
        # Try to acquire the semaphore with a timeout
        acquired = ens_semaphores[ens].acquire(timeout=100)

        if acquired:
            print(f"Semaphore acquired for {ens}.")
            # Add logic to be executed after acquiring the semaphore
        else:
            print(f"Timeout for {ens}, semaphore was not acquired within 10 seconds.")
            # Add logic to be executed in case of a timeout
            
        time.sleep(3)

        return "200"
        
    except requests.exceptions.HTTPError as err:
        print("HTTP Error:", err)
        return "404"
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return "404"

@method
def send_notification_voip_invite(ens, calleer):
    # ens is the destination
    # callee is the sender 
    url = "https://us-central1-arnacon-nl.cloudfunctions.net/voip_noti"
    print(ens)
    print(calleer)
    payload = { 'ens': ens, 'calleer':calleer , 'domain': config['server_name'] }


@method
def send_notification(ens) -> str:
    url = "https://us-central1-arnacon-nl.cloudfunctions.net/send_noti" # Sends the user the notification if the device is not registered
    payload = { 'ens': ens }
    return common_part(url, payload, ens)


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

	url = "https://us-central1-arnacon-nl.cloudfunctions.net/voip_noti"
	payload = { 'ens': user_called, 'callee':user_id , 'domain':config['server_name'] }
      
	response = requests.post(url, json=payload)
	response.raise_for_status()  # This will raise an HTTPError if the HTTP request returned an unsuccessful status code

	return response.status_code # If succesful then 200

@method
def notify_success_reg(ens) -> str:
    print(ens)
    print(str(type(ens)))
    if ens in ens_semaphores:
        ens_semaphores[ens].release()
        print(f"Semaphore released for {ens}")
        del ens_semaphores[ens]

    return "200"


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

			if function_name == "provide_credentials":
				signature = data['sign']
				call_id = data['call_id']
				response = provide_credentials(user_ens,signature,call_id)

			elif function_name == "provide_invite_encrypted_credentials":

				identity = data['identity']
				response = provide_invite_encrypted_credentials(user_ens,identity)


			elif function_name == "send_notification":

				response = send_notification(user_ens)
			

			elif function_name == "notify_success_reg":

				response = notify_success_reg(user_ens)


			elif function_name == "send_notification_voip":

				callee = data['callee'] # destination of the call
				signature = data['sign']
				data_signed = data['data']
				response = send_notification_voip(user_ens, signature,data_signed, callee)
				
			elif function_name == "check_if_user_valid": # RECENT 29/4/2024 function update
				
				signature = data['sign']
				data_signed = data['data']
				response = check_if_user_valid(user_ens,signature,data_signed)

		except json.JSONDecodeError:
			response = "error"
			print("Received data (raw - error):", post_data.decode('utf-8'))

		print(response)
            
		if response == "200":
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
