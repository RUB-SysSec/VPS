import __builtin__

class Registers(object):

	def to_str(self, reg):
		raise NotImplementedError("String lookup is not implemented.")

	def to_idx(self, reg_str):
		raise NotImplementedError("Index lookup is not implemented.")

# Use __builtin__ to share this global variable between all modules.
__builtin__.REGISTERS = Registers()