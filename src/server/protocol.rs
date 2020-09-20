use std::cmp::Ordering;
use std::hash::{ Hash, Hasher };
use std::io::Result;
use std::net::{ Ipv4Addr, Ipv6Addr };

use crate::server::buffer::PacketBuffer;

// --------------------------------------------------------------------------------------------
/// DNSHeader Representation...
// TODO: Change the struct fields to private.
// TODO: Ability to build the Header using Builder pattern.
#[derive(Clone, Debug, Default)]
pub struct DNSHeader {
	// Packet Identifier
	pub id: u16,							// 16 bits

	pub response: bool,						// 1 bit
	pub opcode: u8,							// 4 bits
	pub authoritative_answer: bool,			// 1 bit
	pub truncated_message: bool,			// 1 bit
	pub recursion_desired: bool,			// 1 bit
	pub recursion_available: bool,			// 1 bit
	pub z: bool,							// 1 bit
	pub checking_disabled: bool,			// 1 bit
	pub authed_data: bool,					// 1 bit
	pub rescode: ResultCode,				// 4 bits

	pub questions: u16,						// 16 bits
	pub answers: u16,						// 16 bits
	pub authoritative_entries: u16,			// 16 bits
	pub additional_entries: u16,			// 16 bits
}

impl DNSHeader {
    pub fn new() -> Self {
        Self {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            additional_entries: 0,
        }
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
    	// The first 16 bits are ID...
    	self.id = buffer.read_u16()?;

    	// The next 16 bits consits of various values...
    	let flags = buffer.read_u16()?;
    	let a = (flags >> 8) as u8;
    	let b = (flags & 0xFF) as u8;

    	// Getting the bit values from the 1st byte, starting from LSB...
    	self.recursion_desired		= (a & (1 << 0)) > 0;
    	self.truncated_message		= (a & (1 << 1)) > 0;
    	self.authoritative_answer 	= (a & (1 << 2)) > 0;
    	self.opcode 				= (a >> 3) & 0x0F;
    	self.response				= (a & (1 << 7)) > 0;

    	// Getting the bit values from the 2nd byte, starting from LSB...
    	self.rescode 				= ResultCode::from_num(b & 0x0F);
    	self.checking_disabled		= (b & (1 << 4)) > 0;
    	self.authed_data 			= (b & (1 << 5)) > 0;
    	self.z						= (b & (1 << 6)) > 0;
    	self.recursion_available	= (b & (1 << 7)) > 0;
    	
    	// Each of the next 16 bits consists of no. of entries in various sections...
    	self.questions 				= buffer.read_u16()?;
    	self.answers 				= buffer.read_u16()?;
    	self.authoritative_entries	= buffer.read_u16()?;
    	self.additional_entries 	= buffer.read_u16()?;
    	
    	Ok(())
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
    	Ok(())
    }
}
// --------------------------------------------------------------------------------------------

/// `QueryType` represents the requested Record Type of a query
#[derive(Clone, PartialEq, Eq, Debug, Copy, Hash)]
pub enum QueryType {
	UNKNOWN(u16),
	A,		//1
}

impl QueryType {
	/// The QueryType can be converted to an integer
	pub fn to_num(&self) -> u16 {
		match *self {
			QueryType::UNKNOWN(x) => x,
			QueryType::A => 1,
		}
	}

	pub fn from_num(num: u16) -> QueryType {
		match num {
			1 => QueryType::A,
			_ => QueryType::UNKNOWN(num),
		}
	}
}

// ResultCode for a DNS Query...
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
	NOERROR		= 0,
	FORMERR		= 1,
	SERVFAIL	= 2,
	NXDOMAIN	= 3,
	NOTIMP		= 4,
	REFUSED		= 5,
}

impl Default for ResultCode {
	fn default() -> Self {
		ResultCode::NOERROR
	}
}

impl ResultCode {
	pub fn from_num(num: u8) -> ResultCode {
		match num {
			1 => ResultCode::FORMERR,
			2 => ResultCode::SERVFAIL,
			3 => ResultCode::NXDOMAIN,
			4 => ResultCode::NOTIMP,
			5 => ResultCode::REFUSED,
			0 | _ => ResultCode::NOERROR,
		}
	}
}
// --------------------------------------------------------------------------------------------

/// Representation of DNSQuestion
// TODO: Change the struct fields to private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSQuestion {
	pub name: String,
	pub q_type: QueryType,
}

impl DNSQuestion {
	/// Create a new DNSQuestion.
	/// `name`	- The Domain Name to query
	/// `qType`	- The record to Query from the domain.
	pub fn new(name: String, q_type: QueryType) -> Self {
		Self { name, q_type }
	}

	pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
		buffer.read_qname(&mut self.name)?;
		self.q_type = QueryType::from_num(buffer.read_u16()?);
		let _ = buffer.read_u16()?; //Class

		Ok(())
	}

	pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
		Ok(())
	}
}
// --------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, Ord)]
pub struct TransientTTL(pub u32);

impl Hash for TransientTTL {
	fn hash<H>(&self, _: &mut H)
	where
		H: Hasher
	{
		// Empty because Transient properties do not need hash during serialization...
	}
}

impl PartialEq<TransientTTL> for TransientTTL {
    fn eq(&self, _: &TransientTTL) -> bool {
        true
    }
}

impl PartialOrd<TransientTTL> for TransientTTL {
    fn partial_cmp(&self, _: &TransientTTL) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}
// --------------------------------------------------------------------------------------------

/// Representation of a DNS Record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DNSRecord {
	UNKNOWN {
		domain: String,
		q_type: u16,
		data_len: u16,
		ttl: TransientTTL,
	}, // 0
	A {
		domain: String,
		addr: Ipv4Addr,
		ttl: TransientTTL,
	}, // 1
}

impl DNSRecord {
	pub fn read<T: PacketBuffer>(buffer: &mut T) -> Result<DNSRecord> {
		let mut domain = String::new();
		buffer.read_qname(&mut domain)?;

		let q_type_num = buffer.read_u16()?;
		let q_type = QueryType::from_num(q_type_num);
		let class = buffer.read_u16()?;
		let ttl_num = buffer.read_u32()?;
		let ttl = TransientTTL(ttl_num);
		let data_len = buffer.read_u16()?;

		match q_type {
			QueryType::A => {
				let raw_addr = buffer.read_u32()?;
				let addr = 	Ipv4Addr::new(
								((raw_addr >> 24) & 0xFF) as u8,
								((raw_addr >> 16) & 0xFF) as u8,
								((raw_addr >> 8) & 0xFF) as u8,
								((raw_addr >> 0) & 0xFF) as u8
							);
				Ok(DNSRecord::A { domain, addr, ttl })
			}
			QueryType::UNKNOWN(_) => {
				buffer.step(data_len as usize)?;
				Ok(DNSRecord::UNKNOWN { domain, q_type: q_type_num, data_len, ttl })
			}
		}
	}

	pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<usize> {
		let start_pos = buffer.pos();
		Ok(buffer.pos() - start_pos)
	}
}
// --------------------------------------------------------------------------------------------

/// Representation of DNS Packet.
// TODO: Change the struct variable to private.
#[derive(Clone, Debug, Default)]
pub struct DNSPacket {
	pub header: DNSHeader,
	pub questions: Vec<DNSQuestion>,
	pub answers: Vec<DNSRecord>,
	pub authorities: Vec<DNSRecord>,
	pub additional: Vec<DNSRecord>,
}

impl DNSPacket {
	pub fn new() -> DNSPacket {
		DNSPacket {
			header: DNSHeader::new(),
			questions: Vec::new(),
			answers: Vec::new(),
			authorities: Vec::new(),
			additional: Vec::new(),
		}
	}

	pub fn from_buffer<T: PacketBuffer>(buffer: &mut T) -> Result<DNSPacket> {
		let mut dns_packet = DNSPacket::new();
		dns_packet.header.read(buffer)?;

		for _ in 0..dns_packet.header.questions {
			let mut question = DNSQuestion::new("".to_string(), QueryType::UNKNOWN(0));
			question.read(buffer)?;
			dns_packet.questions.push(question);
		}

		for _ in 0..dns_packet.header.answers {
			let rec = DNSRecord::read(buffer)?;
			dns_packet.answers.push(rec);
		}

		for _ in 0..dns_packet.header.authoritative_entries {
			let rec = DNSRecord::read(buffer)?;
			dns_packet.authorities.push(rec);
		}

		for _ in 0..dns_packet.header.additional_entries {
			let rec = DNSRecord::read(buffer)?;
			dns_packet.additional.push(rec);
		}

		Ok(dns_packet)
	}

	pub fn write<T: PacketBuffer>(&mut self, buffer: &mut T, max_size: usize) -> Result<()> {
		Ok(())
	}
}