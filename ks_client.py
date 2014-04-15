#! /usr/bin/python

import socket, hashlib, getpass, threading, os
from sys import stdout, stderr

HASH_LENGTH = 32
SEGMENT_SIZE = 2**18

def hsh(x):
	return hashlib.sha256(x).digest()

def parse_plan(plan):
	return ["".join(i) for i in zip(*[iter(plan)]*HASH_LENGTH)]

class FileDownload:
	def __init__(self, path, length, segments, complete):
		self.path, self.length, self.segments, self.complete = path, length, segments, complete

	def download_completion(self, ctx):
		return sum(uuid in ctx.segments for uuid in self.plan)

class Context:
	def __init__(self):
		self.local_dir = os.path.join(os.path.expanduser("~"), ".ks_local")
		self.seg_dir = os.path.join(self.local_dir, "segments")
		self.build_dir = os.path.join(self.local_dir, "build")

	def connect(self, host, port=49999):
		self.sock = socket.socket()
		self.sock.connect((host, port))
		self.sock_file = self.sock.makefile()

		# Perform the CR password authentication.
		nonce = self.sock_file.read(16)
		response = hsh(nonce + hsh(obtain_password()) + nonce)
		self.send(response.encode("hex") + "\n")

		s = self.sock_file.readline().strip()
		if s != "good":
			print >> stderr, "Error from server:", s
			raise SystemExit

	def read_local(self):
		self.segments = set()
		def ensure(p):
			if not os.path.exists(p):
				os.mkdir(p)
		# Make our local storage directory, if it doesn't exist.
		ensure(self.local_dir)
		ensure(self.seg_dir)
		ensure(self.build_dir)
		for uuid in os.listdir(self.seg_dir):
			self.segments.add(uuid.decode("hex"))

	def erase_local(self):
		for uuid in os.listdir(self.seg_dir):
			try:
				uuid.decode("hex")
				path = os.path.join(self.seg_dir, uuid)
				print >> stderr, "deleting", path
				os.unlink(path)
			except ValueError:
				print >> stderr, "Weird file in segment storage:", repr(uuid)

	def write_segment(self, segment, assert_uuid=None):
		uuid = hsh(segment)
		if assert_uuid:
			assert uuid == assert_uuid, "hash on segment doesn't match expectation"
		self.segments.add(uuid)
		with open(os.path.join(self.seg_dir, uuid.encode("hex")), "wb") as fd:
			fd.write(segment)

	def read_segment(self, uuid):
		with open(os.path.join(self.seg_dir, uuid.encode("hex")), "rb") as fd:
			return fd.read()

	def update(self):
		self.command("L")
		self.files = {}
		while True:
			line = self.sock_file.readline().strip()
			if line == ".": break
			path, ints = line.split(":", 1)
			path = path.decode("hex")
			length, segments, complete = map(int, ints.split(":"))
			self.files[path] = FileDownload(path, length, segments, complete)
		for path, f in self.files.items():
			self.command("P", path)
			f.plan = parse_plan(self.get_len_encoded())

	def upload_file(self, path):
		"""upload_file(self, path) -- blockingly upload a file"""
		# Find the name of the file on the server.
		pathname = os.path.split(path)[1]
		segments, plan = [], []
		total_length = 0
		with open(path, "rb") as fd:
			data = fd.read(SEGMENT_SIZE)
			segments.append(data)
			plan.append(hsh(data))
			total_length += len(data)
		self.command("N", pathname, total_length, "".join(plan))
		print >> stderr, "Uploading %i segments." % len(segments)
		for segment in segments:
			self.command("S", segment)

	def download_segment(self, uuid):
		# If we already have a cache of this segment, we're golden.
		if uuid in self.segments:
			return 1
		# Otherwise, try downloading it.
		self.command("O", uuid)
		reply = self.sock_file.readline().strip()
		# The reply may be an error message.
		try:
			length = int(reply)
		except ValueError:
			# The segment is not available, sorry.
			return 0
		segment = self.sock_file.read(length)
		self.write_segment(segment, assert_uuid=uuid)
		return 1

	def download_file(self, path):
		self.command("P", path)
		plan = self.get_len_encoded()
		assert len(plan) % HASH_LENGTH == 0, "invalid plan from server"
		plan = parse_plan(plan)
		# Count up the various kinds of segments.
		already_have = sum(uuid in self.segments for uuid in plan)
		s = "Downloading %i segments." % (len(plan) - already_have)
		if already_have:
			s += " (Already have %i of %i total.)" % (already_have, len(plan))
		if already_have == len(plan):
			s = "Already have all %i segments." % len(plan)
		print >> stderr, s
		success = 0
		for uuid in plan:
			success += self.download_segment(uuid)
		if success != len(plan):
			print >> stderr, "="*40
			print >> stderr, "Not all file segments were available for download!"
			print >> stderr, "The file may not be fully uploaded to the server yet."
			print >> stderr, "Run this download command again to keep trying."
			print >> stderr, "Have: %i/%i segments." % (success, len(plan))
			print >> stderr, "="*40

	def cat_file(self, path):
		self.download_file(path)
		f = self.files[path]
		if f.download_completion(self) != f.segments:
			print >> stderr, "Error: Couldn't fully download file, can't cat it."
			raise SystemExit
		for uuid in f.plan:
			stdout.write(self.read_segment(uuid))

	def delete_file(self, path):
		self.command("D", path)

	def get_local_path(self, f):
		return os.path.join(self.build_dir, f.path)

	def rebuild(self):
		self.read_local()
		self.update()
		for f in self.files.values():
			# Check if the file is already built.
			try:
				stat = os.stat(self.get_local_path(f))
				# If the lengths are equal, assume the file is correct.
				if stat.st_size == f.length:
					print >> stderr, "Skipping: %r" % f.path
					continue
			except OSError:
				# If the file doesn't exist, then we must try to rebuild it.
				pass
			# Check if we have downloaded the whole file.
			if f.download_completion(self) != f.segments:
				continue
			print >> stderr, "Rebuilding: %r -> %r" % (f.path, self.get_local_path(f))
			with open(self.get_local_path(f), "wb") as fd:
				for uuid in f.plan:
					fd.write(self.read_segment(uuid))

	def command(self, cmd, *args):
		self.send(cmd + "".join(str(len(arg) if isinstance(arg, str) else arg)+":" for arg in args) + "\n")
		for arg in args:
			if isinstance(arg, str):
				self.send(arg)

	def send(self, msg):
		self.sock_file.write(msg)
		self.sock_file.flush()

	def get_len_encoded(self):
		reply = self.sock_file.readline().strip()
		try:
			length = int(reply)
		except ValueError:
			print >> stderr, "Server reply:", reply
			raise SystemExit
		return self.sock_file.read(length)

def human_readable_size(x):
	if x < 2**10:
		return "%i bytes" % x
	if x < 2**20:
		return "%.1f KiB" % (x / 2**10.0)
	return "%.1f MiB" % (x / 2**20.0)

if __name__ == "__main__":
	import argparse
	p = argparse.ArgumentParser(prog="ks", description="Up/download files from a ks server.")
	p.add_argument("--host", default="biggerpackage4u.ru", help="Server host.")
	p.add_argument("--port", default="49999", type=int, help="Server port.")
#	p.add_argument("--literally", action="store_true", help="Upload with the remote path being exactly as given, not just the path leaf.")
	p.add_argument("--password", default=None, help="Set password. (Highly insecure!)")
	group = p.add_mutually_exclusive_group(required=True)
	def action(name, h):
		group.add_argument("--"+name, dest="action", action="store_const", const=name, help=h)
	action("up", "Upload the listed local files.")
	action("down", "Download the listed remote files.")
	action("delete", "Delete the listed remote files.")
	action("cat", "Writes the contents of the listed remote files to stdout.")
	action("list", "List all remote files on the server.")
	action("local", "Gives info on total local storage.")
	action("path", "Print the path to the build directory.")
	action("build", "Build all files that can be built from the cache of downloaded segments in the build directory.")
	action("erase-segments", "Erase all downloaded segments.")
	p.add_argument("files", metavar="path", type=str, nargs="*", help="Path to process.")
	args = p.parse_args()

	def obtain_password():
		return args.password or getpass.getpass("Password for server: ")

	ctx = Context()

	if args.action in ("up", "down", "delete", "cat", "list", "build"):
		ctx.connect(args.host, args.port)
		print >> stderr, "Connected to %s:%i." % (args.host, args.port)

	if args.action == "list":
		ctx.read_local()
		ctx.update()
		print >> stderr, "Files on server:", len(ctx.files)
		print "D=downloaded A=available T=total"
		rows = [("size", " (", "D", "/", "A", "/", "T", ")", "")]
		for f in ctx.files.values():
			rows.append((human_readable_size(f.length), " (", str(f.download_completion(ctx)), "/", str(f.complete), "/", str(f.segments), ")", f.path))
		columns = zip(*rows)
		fmt = "".join("%%%is" % max(map(len, col)) for col in columns[:-1])
		for row in rows:
			print >> stderr, fmt % row[:-1], row[-1]
	elif args.action in ("up", "down", "delete", "cat"):
		if args.action in ("down", "cat"):
			ctx.read_local()
		if args.action == "cat":
			ctx.update()
		word = args.action[0].upper() + args.action[1:]
		print >> stderr, "%s %i files..." % (word, len(args.files))
		for f in args.files:
			print >> stderr, "== %r" % f
			getattr(ctx, {
				"up": "upload",
				"down": "download",
				"delete": "delete",
				"cat": "cat",
			}[args.action]+"_file")(f)
	elif args.action == "local":
		ctx.read_local()
		print >> stderr, "Have %i segments locally." % len(ctx.segments)
	elif args.action == "path":
		# Not written to stderr, for scripting purposes!
		print ctx.build_dir
	elif args.action == "build":
		ctx.rebuild()
		print >> stderr, "Done rebuilding."
	elif args.action == "erase-segments":
		ctx.erase_local()
		print >> stderr, "Local segment storage erased."
	else: assert False

