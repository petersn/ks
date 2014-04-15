#! /usr/bin/python

import SocketServer, hashlib, getpass, threading, os, struct

global_lock = threading.Lock()

HASH_LENGTH = 32

def hsh(x):
	return hashlib.sha256(x).digest()

def obtain_password():
	return "asdf"

login_password = hsh(obtain_password())

class DataFile:
	def __init__(self, length, plan):
		assert len(plan) % HASH_LENGTH == 0
		self.length = length
		self.plan = ["".join(i) for i in zip(*[iter(plan)]*HASH_LENGTH)]

	def complete_segments(self, ds):
		"""complete_segments(self, ds) -> number of segments in this file that ds already has"""
		return sum(i in ds.segments for i in self.plan)

class DataStorage:
	def __init__(self):
		# Load all the plans for all the files.
		self.files = {}
		for path in os.listdir("storage/files"):
			with open("storage/files/%s" % path, "rb") as fd:
				length, = struct.unpack("<Q", fd.read(8))
				plan = fd.read()
			self.files[path.decode("hex")] = DataFile(length, plan)
		# Load a map of which segments are downloaded from disk.
		self.segments = set()
		for path in os.listdir("storage/segments"):
			self.segments.add(path.decode("hex"))

	def new_file(self, path, length, plan):
		self.files[path] = DataFile(length, plan)
		# Write the new file to disk, as 8 bytes of length, then the entire plan.
		with open("storage/files/%s" % path.encode("hex"), "wb") as fd:
			fd.write(struct.pack("<Q", length))
			fd.write(plan)

	def delete_file(self, path):
		if path in self.files:
			del self.files[path]
		try:
			os.unlink("storage/files/%s" % path.encode("hex"))
		except OSError:
			pass

	def write_segment(self, segment):
		uuid = hsh(segment)
		self.segments.add(uuid)
		with open("storage/segments/%s" % uuid.encode("hex"), "wb") as fd:
			fd.write(segment)

	def get_segment(self, uuid):
		try:
			with open("storage/segments/%s" % uuid.encode("hex"), "rb") as fd:
				return fd.read()
		except OSError:
			return None

ds = DataStorage()

class TransferServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	allow_reuse_address = True

class TransferHandler(SocketServer.StreamRequestHandler):
	"""Request handler for the TransferSever."""
	def handle(self):
		print "Opening connection."
		# Send the user a challenge string.
		nonce = os.urandom(16)
		self.send(nonce)
		print "Nonce sent."
		# Try to get the hashed password from the user.
		password = self.rfile.readline().strip()
		if password.decode("hex") != hsh(nonce + login_password + nonce):
			self.send("Invalid password.")
			return
		print "Password authentication succeeded."
		self.send("good\n")

		while True:
			command = self.rfile.readline().strip()
			# Empty commands disconnect a client.
			if not command: break
			datagram = self.read_datagram(command)
			def key(*args):
				print "===", datagram["type"], " ".join(repr(datagram[arg]) for arg in args)
			with global_lock:
				if datagram["type"] == "N":
					key("path", "length")
					ds.new_file(datagram["path"], datagram["length"], datagram["plan"])
				elif datagram["type"] == "D":
					key("path")
					ds.delete_file(datagram["path"])
				elif datagram["type"] == "S":
					key()
					ds.write_segment(datagram["segment"])
				elif datagram["type"] == "L":
					key()
					for path, datafile in ds.files.items():
						self.wfile.write("%s:%i:%i:%i\n" % (
							path.encode("hex"),
							datafile.length,
							len(datafile.plan),
							datafile.complete_segments(ds),
						))
					self.wfile.write(".\n")
					self.wfile.flush()
				elif datagram["type"] == "P":
					key("path")
					datafile = ds.files.get(datagram["path"], None)
					if datafile is None:
						self.send("no such file\n")
					else:
						self.send_len_encoded("".join(datafile.plan))
				elif datagram["type"] == "O":
					key()
					segment = ds.get_segment(datagram["uuid"])
					if segment is None:
						self.send("no such segment\n")
					else:
						self.send_len_encoded(segment)
		print "Closing connection gracefully."

	def read_datagram(self, command):
		schema = {
			# New file
			"N": [("path", 255), ("length", None), ("plan", HASH_LENGTH*2048)],
			# Delete file
			"D": [("path", 255)],
			# Segment upload
			"S": [("segment", 2**21)],
			# Get a file listing, with lengths
			"L": [],
			# Get file plan
			"P": [("path", 255)],
			# Download segment
			"O": [("uuid", 32)],
		}[command[0]]
		lengths = map(int, command[1:].split(":")[:-1])
		assert len(lengths) == len(schema)
		datagram = {"type": command[0]}
		for field_desc, length in zip(schema, lengths):
			field, max_length = field_desc
			# None is the sentinel that means use the raw int.
			if max_length == None:
				datagram[field] = length
				continue
			assert length <= max_length
			data = self.rfile.read(length)
			datagram[field] = data
		return datagram

	def send(self, msg):
		self.wfile.write(msg)
		self.wfile.flush()

	def send_len_encoded(self, s):
		self.wfile.write("%i\n" % len(s))
		self.wfile.write(s)
		self.wfile.flush()

PORT = 49999
TransferServer(("", PORT), TransferHandler).serve_forever()
