use std::io::Result;
use std::io::{Error, ErrorKind};

pub trait PacketBuffer {	
	fn get(&mut self, pos: usize) -> Result<u8>;
	fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;	
	fn set(&mut self, pos: usize, val: u8) -> Result<()>;
	fn pos(&self) -> usize;
	fn seek(&mut self, pos: usize) -> Result<()>;
	fn step(&mut self, steps: usize) -> Result<()>;

	fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
		self.set(pos, (val >> 8) as u8)?;
		self.set(pos + 1, (val & 0xFF) as u8)?;

		Ok(())
	}

	fn write(&mut self, val: u8) -> Result<()>;
	
	fn write_u16(&mut self, val: u16) -> Result<()> {
		self.write(((val >> 8) & 0xFF) as u8)?;
		self.write(((val >> 0) & 0xFF) as u8)?;

		Ok(())
	}

	fn write_u32(&mut self, val: u32) -> Result<()> {
		self.write(((val >> 24) & 0xFF) as u8)?;
		self.write(((val >> 16) & 0xFF) as u8)?;
		self.write(((val >> 8) & 0xFF) as u8)?;
		self.write(((val >> 0) & 0xFF) as u8)?;

		Ok(())
	}

	fn write_qname(&mut self, qname: &str) -> Result<()> {
		for label in qname.split(".") {
			let len = label.len();
			if len > 63 {
				return Err(Error::new(ErrorKind::InvalidInput, "Single label exceeds 63 chars"));
			}
			self.write(len as u8)?;
			for b in label.as_bytes() {
				self.write(*b)?;
			}
		}
		Ok(())
	}

	fn read(&mut self) -> Result<u8>;

	fn read_u16(&mut self) -> Result<u16> {
		let ret = ((self.read()? as u16) << 8) 
				| ((self.read()? as u16) << 0);
		Ok(ret)
	}

	fn read_u32(&mut self) -> Result<u32> {
		let ret = ((self.read()? as u32) << 24)
				| ((self.read()? as u32) << 16)
				| ((self.read()? as u32) << 8)
				| ((self.read()? as u32) << 0);
		Ok(ret)
	}

	// Reading encoded domain names and constructing the readable domain name by appending it to outstr...
	// Ex: [3]www[6]google[3]com[0] to www.google.com
	// Ex: [3]www[5]yahoo[2]in[0] to www.yahoo.in
	// www, google, yahoo, in, com in above ex are called labels preceded by the length of the label. The ending is 0.
	fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
		let mut pos = self.pos();

		// The delimeter which will be appended for each label.
		// Initially, it will be empty. Later it will be changed to '.'.
		let mut delimeter = "";

		// Whether or not we've jumped
		let mut jumped = false;

		loop {
			// Each label begins with a length byte. So, get the length of label...
			let len = self.get(pos)?;

			// If len has two MSB set, it means we have to jump to some other position in the packet...
			if (len & 0xC0) == 0xC0 {
				if !jumped {
					self.seek(pos + 2)?;
				}

				// If the two MSBs of the length is set, we can instead expect the length byte to be followed by a second byte. 
				// These two bytes taken together, and removing the two MSB's, indicate the jump position.
				// Calculate the jump position and update the local pos variable...
				let next_byte = self.get(pos + 1)? as u16;
				pos = ((((len as u16) ^ 0xC0) << 8) | next_byte) as usize;

				jumped = true;
				continue;
			}
			// Move forward a single byte i.e., the byte next to length, the start of lablel...
			pos += 1;

			// When the length is 0, it is the end of domain name.
			if len == 0 {
				break;
			}

			outstr.push_str(delimeter);

			// Get the label of len length and append to outstr
			let current_label = self.get_range(pos, len as usize)?;
			outstr.push_str(&String::from_utf8_lossy(current_label).to_lowercase());

			delimeter = ".";

			// Move forward the length of the label...
			pos += len as usize;
		}

	    if !jumped {
    	    self.seek(pos)?;
    	}
		
		Ok(())
	}
}

pub struct BytePacketBuffer {
	buf: [u8; 512],
	pos: usize,
}

impl BytePacketBuffer {
	pub fn new() -> Self {
		Self {
			buf: [0; 512],
			pos: 0,
		}
	}
}

impl Default for BytePacketBuffer {
	fn default() -> Self {
		BytePacketBuffer::new()
	}
}

//TODO: Use own enum to handle errors
impl PacketBuffer for BytePacketBuffer {
	fn get(&mut self, pos: usize) -> Result<u8> {
		if pos >= 512 {
			return Err(Error::new(ErrorKind::InvalidInput, "End of Buffer"));
		}
		Ok(self.buf[pos])
	}

	fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
		if start + len >= 512 {
			return Err(Error::new(ErrorKind::InvalidInput, "End of Buffer"));
		}
		Ok(&self.buf[start..start + len])
	}

	fn read(&mut self) -> Result<u8> {
		if self.pos >= 512 {
			return Err(Error::new(ErrorKind::InvalidInput, "End of Buffer"));
		}
		let ret = self.buf[self.pos];
		self.pos += 1;
		Ok(ret)
	}	

	fn write(&mut self, val: u8) -> Result<()> {
		if self.pos >= 512 {
			return Err(Error::new(ErrorKind::InvalidInput, "End of Buffer"));
		}
		self.buf[self.pos] = val;
		self.pos += 1;
		Ok(())
	}

	fn set(&mut self, pos: usize, val: u8) -> Result<()> {
		if pos >= 512 {
			return Err(Error::new(ErrorKind::InvalidInput, "End of Buffer"));
		}
		self.buf[pos] = val;
		Ok(())
	}

	fn pos(&self) -> usize {
		self.pos
	}

	fn seek(&mut self, pos: usize) -> Result<()> {
		self.pos = pos;
		Ok(())
	}

	fn step(&mut self, steps: usize) -> Result<()> {
		self.pos += steps;
		Ok(())
	}
}