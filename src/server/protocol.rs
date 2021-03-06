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
    	buffer.write_u16(self.id)?;

    	buffer.write(
    			((self.recursion_desired as u8) << 0)
    				| ((self.truncated_message as u8) << 1)
    				| ((self.authoritative_answer as u8) << 2)
    				| (self.opcode << 3)
    				| ((self.response as u8) << 7)
    			)?;

    	buffer.write(
    			(self.rescode.clone() as u8)
    				| ((self.checking_disabled as u8) << 4)
    				| ((self.authed_data as u8) << 5)
    				| ((self.z as u8) << 6)
    				| ((self.recursion_available as u8) << 7)
    			)?;

    	buffer.write_u16(self.questions)?;
    	buffer.write_u16(self.answers)?;
    	buffer.write_u16(self.authoritative_entries)?;
    	buffer.write_u16(self.additional_entries)?;

    	Ok(())
    }
}
// --------------------------------------------------------------------------------------------

/// `QueryType` represents the requested Record Type of a query
#[derive(Clone, PartialEq, Eq, Debug, Copy, Hash)]
pub enum QueryType {
	UNKNOWN(u16),
	A,		//1
	NS,		//2
	CNAME,	//5
	SOA,	//6
	MX,		//15
	TXT,	//16
	AAAA,	//28
	SRV,	//33
	OPT,	//44
}

impl QueryType {
	/// The QueryType can be converted to an integer
	pub fn to_num(&self) -> u16 {
		match *self {
			QueryType::UNKNOWN(x) => x,
			QueryType::A => 1,
			QueryType::NS => 2,
			QueryType::CNAME => 5,
			QueryType::SOA => 6,
			QueryType::MX => 15,
			QueryType::TXT => 16,
			QueryType::AAAA => 28,
			QueryType::SRV => 33,
			QueryType::OPT => 44,
		}
	}

	pub fn from_num(num: u16) -> QueryType {
		match num {
			1 => QueryType::A,
			2 => QueryType::NS,
			5 => QueryType::CNAME,
			6 => QueryType::SOA,
			15 => QueryType::MX,
			16 => QueryType:: TXT,
			28 => QueryType::AAAA,
			33 => QueryType::SRV,
			44 => QueryType::OPT,
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
		buffer.write_qname(&self.name)?;			// Domain name
		buffer.write_u16(self.q_type.to_num())?;	// QueryType
		buffer.write_u16(1)?;						// Class
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
	NS {
		domain: String,
		host: String,
		ttl: TransientTTL,
	}, // 2
	CNAME {
		domain: String,
		host: String,
		ttl: TransientTTL,
	}, // 5
	SOA {
		domain: String,
		m_name: String,
		r_name: String,
		serial: u32,
		refresh: u32,
		retry: u32,
		expire: u32,
		minimum: u32,
		ttl: TransientTTL,
	}, // 6
	MX {
		domain: String,
		priority: u16,
		host: String,
		ttl: TransientTTL,
	}, // 15
	TXT {
		domain: String,
		data: String,
		ttl: TransientTTL,
	}, // 16
	AAAA {
		domain: String,
		addr: Ipv6Addr,
		ttl: TransientTTL,
	}, // 28
	SRV {
		domain: String,
		priority: u16,
		weight: u16,
		port: u16,
		host: String,
		ttl: TransientTTL,
	}, // 33
	OPT {
		packet_len: u16,
		flags: u32,
		data: String,
	}, // 41
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
			QueryType::AAAA => {
				let raw_addr1 = buffer.read_u32()?;
				let raw_addr2 = buffer.read_u32()?;
				let raw_addr3 = buffer.read_u32()?;
				let raw_addr4 = buffer.read_u32()?;
				let addr = 	Ipv6Addr::new(
								((raw_addr1 >> 16) & 0xFFFF) as u16,
								((raw_addr1 >> 0) & 0xFFFF) as u16,
								((raw_addr2 >> 16) & 0xFFFF) as u16,
								((raw_addr2 >> 0) & 0xFFFF) as u16,
								((raw_addr3 >> 16) & 0xFFFF) as u16,
								((raw_addr3 >> 0) & 0xFFFF) as u16,
								((raw_addr4 >> 16) & 0xFFFF) as u16,
								((raw_addr4 >> 0) & 0xFFFF) as u16,								
							);
				Ok(DNSRecord::AAAA{ domain, addr, ttl })
			}
			QueryType::NS => {
				let mut host = String::new();
				buffer.read_qname(&mut host)?;
				Ok(DNSRecord::NS{ domain, host, ttl })
			}
			QueryType::CNAME => {
				let mut host = String::new();
				buffer.read_qname(&mut host)?;
				Ok(DNSRecord::CNAME{ domain, host, ttl })
			}
			QueryType::SRV => {
				let priority = buffer.read_u16()?;
				let weight = buffer.read_u16()?;
				let port = buffer.read_u16()?;

				let mut host = String::new();
				buffer.read_qname(&mut host)?;

				Ok(DNSRecord::SRV{ domain, priority, weight, port, host, ttl })
			}
			QueryType::MX => {
				let priority = buffer.read_u16()?;

				let mut host = String::new();
				buffer.read_qname(&mut host)?;

				Ok(DNSRecord::MX{ domain, priority, host, ttl })
			}
			QueryType::SOA => {
				let mut m_name = String::new();
				buffer.read_qname(&mut m_name)?;

				let mut r_name = String::new();
				buffer.read_qname(&mut r_name)?;

				let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum = buffer.read_u32()?;

				Ok(DNSRecord::SOA{ domain, m_name, r_name, serial, refresh, retry, expire, minimum, ttl })
			}
			QueryType::TXT => {
				let mut data = String::new();

				let pos = buffer.pos();
				data.push_str(&String::from_utf8_lossy(buffer.get_range(pos, data_len as usize)?));
				buffer.step(data_len as usize)?;

				Ok(DNSRecord::TXT{ domain, data, ttl })
			}
			QueryType::OPT => {
				let mut data = String::new();

				let pos = buffer.pos();
				data.push_str(&String::from_utf8_lossy(buffer.get_range(pos, data_len as usize)?));
				buffer.step(data_len as usize)?;

				Ok(DNSRecord::OPT{
					packet_len: class,
					flags: ttl_num,
					data
				})
			}
			QueryType::UNKNOWN(_) => {
				buffer.step(data_len as usize)?;
				Ok(DNSRecord::UNKNOWN { domain, q_type: q_type_num, data_len, ttl })
			}
		}
	}

	pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<usize> {
		let start_pos = buffer.pos();

		match *self {
			DNSRecord::A {
				ref domain,
				ref addr,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::A.to_num())?;	// QueryType
				buffer.write_u16(1)?;						// Class
				buffer.write_u32(ttl)?;						// TTL
				buffer.write_u16(4)?;						// DataLength

				let octets = addr.octets();					// IPV4Address
				buffer.write(octets[0])?;
				buffer.write(octets[1])?;
				buffer.write(octets[2])?;
				buffer.write(octets[3])?;
			} // A
			DNSRecord::AAAA {
				ref domain,
				ref addr,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::AAAA.to_num())?;	// QueryType
				buffer.write_u16(1)?;							// Class
				buffer.write_u32(ttl)?;							// TTL
				buffer.write_u32(16)?;							// DataLength

				for octet in &addr.segments() {					// IPV6Address
					buffer.write_u16(*octet)?;
				}
			} // AAAA
			DNSRecord::NS {
				ref domain,
				ref host,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::NS.to_num())?;		// QueryType
				buffer.write_u16(1)?;							// Class
				buffer.write_u32(ttl)?;							// TTL

				let pos = buffer.pos();
				buffer.write_u16(0)?;							// Dummy DataLength...Correct DataLength will be set after the data is set...

				buffer.write_qname(host)?;

				let data_len = buffer.pos() - (pos + 2);
				buffer.set_u16(pos, data_len as u16)?;			// DataLength at the correct pos
			} // NS
			DNSRecord::CNAME {
				ref domain,
				ref host,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::CNAME.to_num())?;	// QueryType
				buffer.write_u16(1)?;							// Class
				buffer.write_u32(ttl)?;							// TTL

				let pos = buffer.pos();
				buffer.write_u16(0)?;							// // Dummy DataLength...Correct DataLength will be set after the data is set...

				buffer.write_qname(host)?;		

				let data_len = buffer.pos() - (pos + 2);
				buffer.set_u16(pos, data_len as u16)?;			// DataLength at the correct pos
			} //CNAME
			DNSRecord::SRV {
				ref domain,
				priority,
				weight,
				port,
				ref host,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::SRV.to_num())?;	// QueryType
				buffer.write_u16(1)?;						// Class
				buffer.write_u32(ttl)?;						// TTL

				let pos = buffer.pos();
				buffer.write_u16(0)?;						// // Dummy DataLength...Correct DataLength will be set after the data is set...

				buffer.write_u16(priority)?;
				buffer.write_u16(weight)?;
				buffer.write_u16(port)?;
				buffer.write_qname(host)?;

				let data_len = buffer.pos() - (pos + 2);
				buffer.set_u16(pos, data_len as u16)?;		// DataLength at the correct pos
			} // SRV
			DNSRecord::MX {
				ref domain,
				priority,
				ref host,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::MX.to_num())?;	// QueryType
				buffer.write_u16(1)?;						// Class
				buffer.write_u32(ttl)?;						// TTL

				let pos = buffer.pos();
				buffer.write_u16(0)?;						// // Dummy DataLength...Correct DataLength will be set after the data is set...

				buffer.write_u16(priority)?;
				buffer.write_qname(host)?;

				let data_len = buffer.pos() - (pos + 2);
				buffer.set_u16(pos, data_len as u16)?;		// DataLengh at the correct pos
			} // MX
			DNSRecord::SOA {
				ref domain,
				ref m_name,
				ref r_name,
				serial, 
				refresh,
				retry,
				expire,
				minimum,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::SOA.to_num())?;	// QueryType
				buffer.write_u16(1)?;						// Class
				buffer.write_u32(ttl)?;						// TTL

				let pos = buffer.pos();
				buffer.write_u16(0)?;						// // Dummy DataLength...Correct DataLength will be set after the data is set...

				buffer.write_qname(m_name)?;
				buffer.write_qname(r_name)?;
				buffer.write_u32(serial)?;
				buffer.write_u32(refresh)?;
				buffer.write_u32(retry)?;
				buffer.write_u32(expire)?;
				buffer.write_u32(minimum)?;

				let data_len = buffer.pos() - (pos + 2);
				buffer.set_u16(pos, data_len as u16)?;		// DataLength at the correct pos
			} // SOA
			DNSRecord::TXT {
				ref domain,
				ref data,
				ttl: TransientTTL(ttl),
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::TXT.to_num())?;	// QueryType
				buffer.write_u16(1)?;						// Class
				buffer.write_u32(ttl)?;						// TTL
				buffer.write_u16(data.len() as u16)?;		// DataLength

				for b in data.as_bytes() {
					buffer.write(*b)?;
				}
			} // TXT	
			DNSRecord::OPT { .. } => { } // OPT
			DNSRecord::UNKNOWN {..} => {
				println!("Skipping Record :: {:?}", self);
			} // UNKNOWN
		}

		Ok(buffer.pos() - start_pos)
	}

	pub fn get_query_type(&self) -> QueryType {
		match *self {
			DNSRecord::A { .. } => QueryType::A,
			DNSRecord::AAAA { .. } => QueryType::AAAA,
			DNSRecord::NS { .. } => QueryType::NS,
			DNSRecord::CNAME { .. } => QueryType::CNAME,
			DNSRecord::SRV { .. } => QueryType::SRV,
			DNSRecord::MX { .. } => QueryType::MX,
			DNSRecord::SOA { .. } => QueryType::SOA,
			DNSRecord::TXT { .. } => QueryType::TXT,
			DNSRecord::OPT { .. } => QueryType::OPT,
			DNSRecord::UNKNOWN { q_type, .. } => QueryType::UNKNOWN(q_type),
		}
	}

	pub fn get_domain(&self) -> Option<String> {
		match *self {
			DNSRecord::A { ref domain, .. }
			| DNSRecord::AAAA { ref domain, .. }
			| DNSRecord::NS { ref domain, .. }
			| DNSRecord::CNAME { ref domain, .. }
			| DNSRecord::SRV { ref domain, .. }
			| DNSRecord::MX { ref domain, .. }
			| DNSRecord::SOA { ref domain, .. }
			| DNSRecord::TXT { ref domain, .. }
			| DNSRecord::UNKNOWN { ref domain, .. } => Some(domain.clone()),
			DNSRecord::OPT { .. } => None,
		}
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

	pub fn write<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
		self.header.questions = self.questions.len() as u16;
		self.header.answers = self.answers.len() as u16;
		self.header.authoritative_entries = self.authorities.len() as u16;
		self.header.additional_entries = self.additional.len() as u16;

		self.header.write(buffer)?;

		for question in &self.questions {
			question.write(buffer)?;
		}
		for record in &self.answers {
			record.write(buffer)?;
		}
		for record in &self.authorities {
			record.write(buffer)?;
		}
		for record in &self.additional {
			record.write(buffer)?;
		}		
		Ok(())
	}
}